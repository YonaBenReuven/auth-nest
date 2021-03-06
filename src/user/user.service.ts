import { Injectable, Inject, Optional, ConflictException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService, JwtSignOptions, JwtVerifyOptions } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { CookieOptions, Response } from 'express';
import { Repository, DeepPartial, SelectQueryBuilder } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as base64 from 'base-64';
import * as randomstring from 'randomstring';
import { render } from 'mustache';
import * as crypto from 'crypto';

import { AuthConfigAccessLogger, AuthConfigAccessTokenCookie, AuthConfigAppName, AuthConfigAppNameHe, AuthConfigResetPasswordEmail, AuthConfigRoleAccess, AuthConfigSecretOrKey, AuthConfigTtl, AuthConfigVerificationEmail } from '../common/interfaces/auth-config.interface';
import { RequestUserType } from '../common/interfaces/request-user-type.interface';
import { DEFAULT_MAX_AGE, EMAIL_VERIFIED, jwtConstants, SALT, VERIFICATION_TOKEN } from '../common/constants';
import { MailerInterface, MailAttachments } from '../mails/mailer.interface';
import { LoginErrorCodes } from '../common/loginErrorCodes';
import { ResetPasswordTemplate, VerifyMailTemplate } from '../mails/verifyMail.template';
import { Role } from '../role/role.entity';
import { AccessLoggerService } from '../access-logger/access-logger.service';
import { UserPasswordService } from '../user-password/user-password.service';

import { User } from './user.entity';
import { UserConfig } from './user.config.interface';

const debug = require('debug')('model:User');

@Injectable()
export class UserService {
	private authSecrestOrKey: string;

	constructor(
		@Inject('USER_MODULE_OPTIONS')
		protected config_options: UserConfig,
		@InjectRepository(User)
		protected readonly userRepository: Repository<User>,
		protected readonly jwtService: JwtService,
		protected readonly configService: ConfigService,
		@Optional() @Inject('MailService')
		protected readonly mailer?: MailerInterface,
		@Optional()
		protected readonly accessLoggerService?: AccessLoggerService,
		@Optional()
		protected readonly userPasswordService?: UserPasswordService
	) {
		debug("init", this.userRepository.metadata.name);

		this.authSecrestOrKey = this.configService.get<AuthConfigSecretOrKey>('auth.secretOrKey', jwtConstants.secret);
	}

	async createUser<U extends User = User>(user: DeepPartial<U>) {
		const userCopy = { ...user };
		if (!(user instanceof User)) { // The hash function does not apply for objects that r not User instances. 
			(user as DeepPartial<User>).password = bcrypt.hashSync(user.password, SALT)
		}

		const res = await this.userRepository.save(user);

		if (this.config_options.useUserPassword && user.password) {
			await this.userPasswordService.createUserPassword(res.id, (user as DeepPartial<User>).password);
		}

		if (this.config_options.emailVerification) {
			let userAndToken = await this.generateVerificationTokenAndSave(res);
			this.sendVerificationEmail(userAndToken.username, userAndToken[VERIFICATION_TOKEN], userCopy);
			return userAndToken;
		}

		else return res;
	}
	/**
	 * Gets a user's roles by its id
	 * @param id The user's id
	 * @returns An array of the user's roles' names
	 */
	async getRolesById(id: string) {
		const roles = await this.userRepository
			.createQueryBuilder('user')
			.relation('roles')
			.of(id)
			.loadMany<Role>();

		return roles.map(role => role.name);
	}
	/**
	 * Matches a user's roles to a given array of roles
	 * @param userRoles The user's roles
	 * @param roles The roles that need to be matched to the user's roles
	 * @returns A boolean that indicates if the roles match, i.e. if some of the user's roles are in the given array
	 */
	matchRoles(userRoles: string[], roles: string[]) {
		return userRoles.some(role => roles.includes(role)) || roles.includes("$authenticated")
	}
	/**
	 * Matches a user's roles by its id to a given array of roles
	 * @param id The user's id
	 * @param roles The roles that need to be matched to the user's roles
	 * @returns A boolean that indicates if the roles match, i.e. if some of the user's roles are in the given array
	 */
	async matchRolesById(id: string, roles: string[]) {
		const userRoles = await this.getRolesById(id);
		if (!userRoles) return false;

		return this.matchRoles(userRoles, roles);
	}
	/**
	 * Matches a user's type to an array of entities that extend the User entity
	 * @param type The user's type
	 * @param entities An array of entities that extend the User entity
	 * @returns A boolean that indicates if the type matches, i.e. if the entities include the type
	 */
	matchEntities<T extends Array<typeof User>>(type: string, entities: T) {
		return entities.map(entity => entity.name).includes(type);
	}
	/**
	 * Produces a user's klos by its roles
	 * @param roles An array of strings representing a user's roles
	 * @returns A string that is an encoded version of a user's components and default home page
	 */
	getKlos(roles: string[], roleKeys: string[]) {
		const { a, b } = roles
			.map(role => this.configService.get<AuthConfigRoleAccess[keyof AuthConfigRoleAccess]>(`roleAccess.${role}`))
			.filter(roleAccessConfig => !!roleAccessConfig)
			.reduce(({ a }, { components, defaultHomePage }) => {
				return { a: [...a, ...components], b: defaultHomePage };
			}, { a: [], b: '' } as { a: string[]; b: string; });

		const klo = base64.encode(JSON.stringify({ a, b })).replace(/==|=/gm, '');

		const kl = base64.encode(JSON.stringify(roleKeys)).replace(/==|=/gm, '');

		return { klo, kl };
	}
	/**
	 * Produces a user's klos by its id
	 * @param id The user's id
	 * @returns A string that is an encoded version of a user's components and default home page
	 */
	async getKlosById(id: string) {
		const roles = await this.userRepository
			.createQueryBuilder('user')
			.relation('roles')
			.of(id)
			.loadMany() as Role[];

		const klos = this.getKlos(roles.map(role => role.name), roles.map(role => role.roleKey));

		return klos;
	}
	/**
	 * Validates a user by its username and password
	 * @param username The user's username
	 * @param pass The user's password
	 * @returns If the user's username exists and the password is correct a response is returned consisting of the user's id, username, type, and roles
	 * Otherwise, i.e. if the username doesn't exits or the password is incorrect, null is returned
	 */
	async validateUser(username: string, pass: string, comparePassword = true) {
		const queryBuilder = this.userRepository
			.createQueryBuilder('user')
			.addSelect('user.password')
			.addSelect('user.type')
			.addSelect(this.config_options.emailVerification ? `user.${EMAIL_VERIFIED}` : '')
			.addSelect(this.config_options.emailVerification ? `user.${VERIFICATION_TOKEN}` : '')
			.leftJoinAndSelect('user.roles', 'role')
			.where({ username });

		const retrieve = this.configService.get<boolean>('auth.retrieve_all_userData');

		const extraFieldsQueryBuilder = this.createValidateUserQueryBuilder(queryBuilder, retrieve ? [] : this.config_options.extra_login_fields);
		const user = await extraFieldsQueryBuilder.getOne();

		if (!user)
			throw LoginErrorCodes.NoUsername;

		const enable_access_logger = this.configService.get<AuthConfigAccessLogger>('auth.access_logger');

		if (enable_access_logger && enable_access_logger.enable) {
			let canLogin = await this.accessLoggerService.canLogin(user.id, enable_access_logger.minutes, enable_access_logger.tries);
			if (!canLogin)
				throw LoginErrorCodes.UserBlocked;
		}

		if (!user.password) {
			throw LoginErrorCodes.UserHasNoPassword;
		}

		if (comparePassword && !bcrypt.compareSync(pass, user.password)) {
			enable_access_logger && enable_access_logger.enable && this.accessLoggerService && this.accessLoggerService.loginEvent(user as Partial<User>, false);
			throw LoginErrorCodes.PassDosentMatch;
		}
		if (this.config_options.emailVerification)//user didnt verified his email
			if (!user[EMAIL_VERIFIED]) {
				enable_access_logger && enable_access_logger.enable && this.accessLoggerService && this.accessLoggerService.loginEvent(user as Partial<User>, false);
				throw LoginErrorCodes.EmailNotVerified;
			}
			else if (user[VERIFICATION_TOKEN]) { //user managed to log in even there is a waiting reset-password token for him
				try {
					await this.userRepository.update(user.id, { [VERIFICATION_TOKEN]: null } as Partial<User>);
				}
				catch (error) {
					console.error("Could not update verification token in validateUser:", error);
				}
			}


		if (this.config_options.useUserPassword && this.config_options.force_change_password_year) {
			const shouldChangePass = await this.userPasswordService.changePasswordRequired(user.id);
			if (shouldChangePass)
				throw LoginErrorCodes.UserMustChangePassword;
		}

		if (enable_access_logger && enable_access_logger.enable && this.accessLoggerService) {
			this.accessLoggerService.loginEvent(user as Partial<User>, true);
		}

		const allUserData = retrieve ? user : {};

		const requestUser: RequestUserType = {
			...allUserData,
			id: user.id,
			username: user.username,
			type: user.type,
			roles: user.roles.map(role => role.name),
			roleKeys: user.roles.map(role => role.roleKey)
		}

		return requestUser;

	}

	async verifyEmailByToken(token: string): Promise<boolean> {
		if (this.config_options.emailVerification)
			if (this.userRepository.metadata.propertiesMap[EMAIL_VERIFIED])
				try {
					const verificationSuccess = await this.userRepository.update(
						{ [VERIFICATION_TOKEN]: token } as Partial<User>,
						{ [EMAIL_VERIFIED]: 1, [VERIFICATION_TOKEN]: null } as Partial<User>
					);
					return verificationSuccess.affected ? true : false;
				}
				catch (err) {
					console.error("Error while verify email: %s", err);
					return false;
				}
			else {
				console.error(`Cannot verify emails when "${VERIFICATION_TOKEN}" column dosent exist.`)
				process.exit(1)
			}
	}

	async sendEmail(to: string | Array<string>, subject: string = null, text: string, html: string, attchments: Array<MailAttachments>): Promise<any> {
		if (!this.mailer) throw "No mailer supplied "

		if (!subject) {
			if (this.configService.get<AuthConfigAppName>('app_name')) {
				subject = `Welcome to ${this.configService.get<AuthConfigAppName>('app_name')}!`;
			} else
				subject = "Welcome!"
		}

		console.log('html:', html)

		this.mailer.send({
			from: `${this.configService.get<AuthConfigAppName>("app_name") || this.configService.get<AuthConfigAppNameHe>("app_name_he")} <${process.env.SEND_EMAIL_ADDR}>`, // from: '"Fred Foo 👻" <foo@example.com>', // sender address
			to: to, // list of receivers
			subject, // Subject line
			text, // plain text body
			html, // html body
			attachments: attchments//array of attachments, each object of
		}).then(res => console.log(">Sent email to ", res.accepted)).
			catch(err => console.error(">Error in send mail: %s", err))
	}

	async sendVerificationEmail(email: string, token: string, user?: DeepPartial<User>) {
		const verification_email_config = this.configService.get<AuthConfigVerificationEmail>('auth.verification_email');
		let sitename = this.configService.get<AuthConfigAppNameHe>('app_name_he') || "אתר תוצרת הילמה",
			htmlConf = verification_email_config.html,
			verifyPath = verification_email_config.verifyPath || "/verify",
			imagePlace = verification_email_config.logoDiv,
			logoPath = verification_email_config.logoPath,
			subject = verification_email_config.subject || "ברוכים הבאים! צעד אחרון ואתם רשומים🤩",
			text = verification_email_config.text;

		if (!htmlConf)
			htmlConf = VerifyMailTemplate;
		let html = render(htmlConf, { sitename, verifyPath, token, placeForLogo: imagePlace });
		text && (text = render(text, { sitename, verifyPath, token, placeForLogo: imagePlace }));

		const attchments = logoPath && imagePlace ? [{ cid: "logo", path: logoPath }] : [];
		this.sendEmail(email, subject, text, html, attchments);
	}

	generateVerificationToken() {
		let buffer = crypto.randomBytes(50);
		if (buffer) return buffer.toString('hex')
		else throw new Error("Failed to generate token")
	};

	async generateVerificationTokenAndSave(user: DeepPartial<User>) {
		try {
			let token = this.generateVerificationToken();
			await this.userRepository.update(user.id ?? { username: user.username }, { [VERIFICATION_TOKEN]: token } as Partial<User>);

			return { ...user, [VERIFICATION_TOKEN]: token }
		} catch (err) {
			console.error("Error in generateVerificationTokenAndSave:", err);
			throw "Could not generate token";
		}
	}

	/**
		 * This function generates a change-password token for EMAIL, and sends the email.
		 * @param {string} email
		 */
	async sendChangePasswordEmail(email: string) {
		let token = await (await this.generateVerificationTokenAndSave({ username: email }))[VERIFICATION_TOKEN];
		const reset_pass_email_config = this.configService.get<AuthConfigResetPasswordEmail>('auth.reset_password_email');
		let sitename = this.configService.get<AuthConfigAppName>('app_name_he') || "אתר תוצרת הילמה",
			htmlConf = reset_pass_email_config.html,
			changePath = reset_pass_email_config.changePath || "/changePassword/",
			imagePlace = reset_pass_email_config.logoDiv,
			logoPath = reset_pass_email_config.logoPath,
			subject = reset_pass_email_config.subject || "היי, כאן משנים את הסיסמה",
			text = reset_pass_email_config.text;

		if (!htmlConf)
			htmlConf = ResetPasswordTemplate;
		let html = render(htmlConf, { sitename, changePath, token, placeForLogo: imagePlace, email });
		text && (text = render(text, { sitename, changePath, token, placeForLogo: imagePlace, email }));

		const attchments = logoPath && imagePlace ? [{ cid: "logo", path: logoPath }] : [];
		this.sendEmail(email, subject, text, html, attchments);
	}


	async changePasswordWithToken(token: string, email: string, newPassword: string) {
		if (!token || !newPassword) {
			debug('you cannot change password without token or string');
			return false;
		}
		if (this.userRepository.metadata.propertiesMap[EMAIL_VERIFIED])
			try {
				const hashedPassword = bcrypt.hashSync(newPassword, SALT);

				let user: User;
				if (this.config_options.useUserPassword) {
					user = await this.userRepository
						.createQueryBuilder('user')
						.select('user.id')
						.where('user.username = :email', { email })
						.getOne();
					if (!user)
						throw "No user matching this username:" + email;
					const canChangePassword = await this.userPasswordService.checkPassword(user.id, newPassword);
					if (!canChangePassword) {
						debug("Password already used")
						return { success: false };
					}
				}

				const updateSuccess = await this.userRepository.update(
					{ username: email, [VERIFICATION_TOKEN]: token } as Partial<User>,
					{ password: hashedPassword, [VERIFICATION_TOKEN]: null } as Partial<User>);

				if (this.config_options.useUserPassword) {
					await this.userPasswordService.createUserPassword(user.id, newPassword);
				}

				return updateSuccess.affected ? true : false;
			}
			catch (err) {
				console.error("Error while change password with token email: %s", err);
				return false;
			}
		else {
			console.error(`Cannot change password when "${VERIFICATION_TOKEN}" column dosent exist.`)
			process.exit(1)
		}
	}


	/**
	 * Creates a login response for a controller's endpoint
	 * @param user A user request type created by validate user
	 * @param res The response object from the controller's endpoint
	 * @param ttl The expiration of the cookies and access token in ms. default to the ttl in `configuration.ts` or 5 hours
	 * @returns A login response consisting of the user request and the cookies that are attached to the response object
	 */
	login(user: RequestUserType, res: Response, ttl?: number, cookies_options?: CookieOptions) {
		ttl = ttl ?? this.configService.get<AuthConfigTtl[keyof AuthConfigTtl]>(`auth.ttl.${user.type}`) ?? DEFAULT_MAX_AGE;

		const accessTokenCookie = this.configService.get<AuthConfigAccessTokenCookie>('auth.accessToken_cookie') ?? 'access_token';

		const klos = this.getKlos(user.roles, user.roleKeys);

		const requestUser: RequestUserType & Record<string, any> = {
			id: user.id,
			username: user.username,
			type: user.type,
			roles: user.roles,
			roleKeys: user.roleKeys
		}

		const extra_login_fields = this.config_options.extra_login_fields || [];

		extra_login_fields.forEach(field => {
			requestUser[field] = user[field];
		});

		const accessToken = this.createAccessToken(requestUser, { expiresIn: ttl });

		const cookies = {
			...klos,
			[accessTokenCookie]: accessToken,
			kloo: this.generateStringInRange(accessToken, klos.klo),
			klk: this.generateStringInRange(accessToken, klos.klo),
		};

		for (const key in cookies) {
			res.cookie(key, cookies[key as keyof typeof cookies], { maxAge: ttl * 1000, ...cookies_options });//because the TTL is in seconds, and maxAge is in miliseconds.
		}

		const body = { ...user, ...cookies };

		return body;
	}

	// With a givan userId, if oldPassword is matching, change to newPassword
	async changePassword(userId: string, oldPassword: string, newPassword: string, checkPassword: boolean = this.config_options.useUserPassword) {
		const user = await this.userRepository
			.createQueryBuilder('user')
			.addSelect('user.password')
			.where({ id: userId })
			.getOne();

		if (!user) throw new NotFoundException('Not Found', `Could not find user with id '${userId}'`);

		if (!bcrypt.compareSync(oldPassword, user.password)) throw new ConflictException('Conflict', 'Passwords do not match');

		return this.setPassword(userId, newPassword, checkPassword);
	}

	// With a givan userId, change directly to newPassword (usefull for admins, for example)
	async setPassword(userId: string, newPassword: string, checkPassword: boolean = this.config_options.useUserPassword) {
		if (checkPassword) {
			const canChangePassword = await this.userPasswordService.checkPassword(userId, newPassword);
			if (!canChangePassword) throw new ConflictException('Conflict', 'Password has already been used in past three times');
		}

		const password = await bcrypt.hash(newPassword, SALT);
		const updated = await this.userRepository.update(userId, { password });

		await this.userPasswordService.createUserPassword(userId, newPassword);

		return updated;
	}


	async forceLogin(user: any, field: string, res: Response, roles?: Role[], cookies_options?: CookieOptions) {
		if (!user[field]) {
			debug("User tried to force login:", user);
			return {}
		}
		let userInst = await this.userRepository.createQueryBuilder('user')
			.addSelect('user.type')
			.leftJoinAndSelect('user.roles', 'role')
			.where({ username: user[field] }).getOne();
		if (userInst) {
			debug('Logged using forced login:', userInst)//WE DONT CARE HOW DID YOU LOGGED IN

			return this.login({ ...userInst, roles: userInst.roles.map(role => role.name), roleKeys: userInst.roles.map(role => role.roleKey) }, res, null, cookies_options);

		}
		else {
			//Create new user ~WITH NO PASSWORD~
			let newUser = { ...user, username: user[field], password: null, [EMAIL_VERIFIED]: 1, roles: roles || [] }
			newUser = await this.userRepository.save(newUser);
			debug("New user instance: ", newUser);
			return this.login({ ...newUser, roles: newUser.roles.map(role => role.name), type: this.userRepository.metadata.name }, res, null, cookies_options);
		}
	}

	async forceLoginUpdateFields(user, uniqeField, fields: Array<string>, res: Response, roles?: Role[], cookies_options?: CookieOptions) {
		/**
		 * @param user 
		 * @param uniqeField - identified field 
		 * @param fields - the fields that we want to update for this user, in case they've changed.
		 * @param res - http response, for cookies 
		 */


		if (!user[uniqeField]) {
			debug("User tried to force login:", user);
			return {}
		}
		let userInst = await this.userRepository.createQueryBuilder('user')
			.addSelect('user.type')
			.leftJoinAndSelect('user.roles', 'role')
			.where({ username: user[uniqeField] }).getOne();
		if (userInst) {
			let haveChange = false;

			for (let key of fields) {
				if (userInst[key] != user[key]) {
					userInst[key] = user[key];
					haveChange = true;
				}
			}
			haveChange && this.userRepository.save(userInst);
			return this.login({ ...userInst, roles: userInst.roles.map(role => role.name), roleKeys: userInst.roles.map(role => role.roleKey) }, res, null, cookies_options);
		}
		else {
			let newUser = { ...user, username: user[uniqeField], password: null, [EMAIL_VERIFIED]: 1, roles: roles || [] }
			newUser = await this.userRepository.save(newUser);
			debug("New user instance: ", newUser);
			return this.login({ ...newUser, roles: roles.map(role => role.name), roleKeys: roles.map(role => role.roleKey), type: this.userRepository.metadata.name }, res, null, cookies_options);
		}
	}


	async allUsers(): Promise<User[]> {
		return this.userRepository.find();
	}

	generateStringInRange(string1: string, string2: string) {
		const [shortLength, longLength] = [string1.length, string2.length].sort((a, b) => a - b);

		return randomstring.generate({
			length: Math.floor(Math.random() * (1 + longLength - shortLength)) + shortLength + Math.floor(Math.random() * 21) - 10
		});
	}

	private createValidateUserQueryBuilder(queryBuilder: SelectQueryBuilder<User>, fields: string[] = []): SelectQueryBuilder<User> {
		if (fields.length === 0) return queryBuilder;

		const [field, ...rest] = fields;

		const fieldQueryBuilder = queryBuilder.addSelect(`user.${field}`);

		return this.createValidateUserQueryBuilder(fieldQueryBuilder, rest);
	}

	createAccessToken<T extends RequestUserType = RequestUserType>(payload: T, options: JwtSignOptions = {}): string {
		return this.jwtService.sign(payload, {
			secret: this.authSecrestOrKey,
			...options,
		});
	}

	verifyAccessToken<T extends RequestUserType = RequestUserType>(token: string, options: JwtVerifyOptions = {}): Promise<T> {
		return this.jwtService.verifyAsync<T>(token, {
			secret: this.authSecrestOrKey,
			...options,
		});
	}
}

