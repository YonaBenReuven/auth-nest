import { Injectable, Inject } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { Repository, DeepPartial, Any } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as base64 from 'base-64';
import * as randomstring from 'randomstring';

import { User } from './user.entity';
import { Role } from 'src/role/role.entity';
import { RequestUserType } from 'src/common/interfaces/request-user-type.interface';
import { RoleAccessConfig } from 'src/common/interfaces/role-access-config.interface';
import { SALT } from 'src/common/constants';
import { ConfigService } from '@nestjs/config';
import UserConfigOptions from './userConfigOptions';
import * as crypto from 'crypto';

@Injectable()
export class UserService {

	roleAccessConfig: RoleAccessConfig;

	constructor(
		@Inject('CONFIG_OPTIONS') private config_options: UserConfigOptions,
		@InjectRepository(User)
		private readonly userRepository: Repository<User>,
		private readonly jwtService: JwtService,
		protected readonly configService: ConfigService
	) {
		this.roleAccessConfig = require('../../role-access.config.json');
	}

	async createUser(user: DeepPartial<User>) {
		let res = await this.userRepository.save(user);
		if (this.config_options.emailVerification) {
			let userAndToken = await this.generateVerificationTokenAndSave(res);
			this.sendVerificationEmail(userAndToken.username, userAndToken.verificationToken);
			return userAndToken;
		}
		else res;
	}

	async getRolesById(id: string) {
		const roles = await this.userRepository
			.createQueryBuilder('user')
			.relation('roles')
			.of(id)
			.loadMany() as Role[];

		return roles.map(role => role.name);
	}

	matchRoles(userRoles: string[], roles: string[]) {
		return userRoles.some(role => roles.includes(role));
	}

	async matchRolesById(id: string, roles: string[]) {
		const userRoles = await this.getRolesById(id);
		if (!userRoles) return false;

		return this.matchRoles(userRoles, roles);
	}

	matchEntities<T extends Array<typeof User>>(type: string, entities: T) {
		return entities.map(entity => entity.name).includes(type);
	}

	getKlos(roles: string[]) {
		const { a, b } = roles
			.map(role => this.roleAccessConfig[role])
			.reduce(({ a }, { components, defaultHomePage }) => {
				return { a: [...a, ...components], b: defaultHomePage };
			}, { a: [], b: '' } as { a: string[]; b: string; });

		const klo = base64.encode(JSON.stringify({ a, b }));

		return klo;
	}

	async getKlosById(id: string) {
		const roles = await this.userRepository
			.createQueryBuilder('user')
			.relation('roles')
			.of(id)
			.loadMany() as Role[];

		const klo = this.getKlos(roles.map(role => role.name));

		return klo;
	}

	async validateUser(username: string, pass: string) {
		const user: any = await this.userRepository
			.createQueryBuilder('user')
			.addSelect('user.password')
			.addSelect('user.type')
			.addSelect(this.config_options.emailVerification ? 'user.emailVerified' : '')
			.leftJoinAndSelect('user.roles', 'role')
			.where({ username })
			.getOne();

		if (!user) return null;
		if (!bcrypt.compareSync(pass, user.password)) return null;
		if (this.config_options.emailVerification && !user.emailVerified)//user didnt verified his email
			return null;

		const requestUser: RequestUserType = {
			id: user.id,
			username: user.username,
			type: user.type,
			roles: user.roles.map(role => role.name)
		}

		return requestUser;
	}

	async verifyEmailByToken(token: string): Promise<boolean> {
		if (this.userRepository.metadata.propertiesMap.emailVerified)
			try {
				const verificationSuccess = await this.userRepository.manager.query(
					'UPDATE user SET emailVerified=1,verificationToken=null WHERE verificationToken=?', [token]);

				return verificationSuccess.changedRows
			}
			catch (err) {
				console.error("Error while verify email: %s", err);
				return false;
			}
		else {
			console.error("Cannot verify emails when `verificationToken` column dosent exist.")
			process.exit(1)
		}
	}

	async sendEmail(to: string, subject: string = null, text: string, html: string, attchments: Array<MailAttachments>): Promise<any> {
		if (!this.config_options.mailer) throw "No mailer supplied "

		if (!subject) {
			if (this.configService.get('app_name')) {
				subject = `Welcome to ${this.configService.get('app_name')}!`;
			} else
				subject = "Welcome!"
		}

		this.config_options.mailer.send({
			from: `${this.config_options.fromName || ""} <${this.config_options.emailAddress}>`, // from: '"Fred Foo 👻" <foo@example.com>', // sender address
			to: to, // list of receivers
			subject, // Subject line
			text, // plain text body
			html, // html body
			attachments: attchments//array of attachments, each object of
		}).then(res => console.log(">Sent email to ", res.accepted)).
			catch(err => console.error(">Error in send mail: %s", err))
	}

	async sendVerificationEmail(email: string, token: string) {
		const sitename = this.configService.get('app_name_he') || "אתר תוצרת הילמה";
		let verifyPath = this.config_options.verifyPath;

		let html = `<div style={{ direction: 'rtl' }}>
        <h1 >ברוכים הבאים ל${sitename}!</h1>
        <p>נשאר רק עוד צעד קטן כדי לסיים את ההרשמה שלכם!</p>
        <p>לחצו על הקישור <a href="https://${process.env.REACT_APP_DOMAIN}/api${verifyPath}?token=${token}">כאן</a> כדי לאמת את כתובת המייל💚</p>
        ${this.config_options.pathToLogo ? `<div style="width:100%">
			<img src="cid:logo"></img>
        </div>`: ""}
	</div>`
		const attchments = [{ cid: "logo", path: this.config_options.pathToLogo }];
		this.sendEmail(email, "ברוכים הבאים! צעד אחרון ואתם רשומים🤩", "", html, attchments);
	}

	generateVerificationToken() {
		let buffer = crypto.randomBytes(50);
		if (buffer) return buffer.toString('hex')
		else throw new Error("Failed to generate token")
	};

	async generateVerificationTokenAndSave(user: DeepPartial<User>) {
		try {
			let token = this.generateVerificationToken();
			const updateSuccess = await this.userRepository.manager.query(
				'UPDATE user SET verificationToken=? WHERE id=?', [token, user.id]);

			return { ...user, verificationToken: token }
		} catch (err) {

		}
	}


	login(user: RequestUserType) {
		return {
			...user,
			kl: randomstring.generate({ length: 68 }),
			kloo: randomstring.generate({ length: 68 }),
			klk: randomstring.generate({ length: 68 }),
			klo: this.getKlos(user.roles),
			access_token: this.jwtService.sign(user)
		};
	}

	// With a givan userId, if oldPassword is matching, change to newPassword
	async changePassword(userId: string | number, oldPassword: string, newPassword: string) {
		const user = await this.userRepository
			.createQueryBuilder('user')
			.addSelect('user.password')
			.where({ id: userId })
			.getOne();

		if (!user) return `Could not find user with id ${userId}`;
		if (!bcrypt.compareSync(oldPassword, user.password)) return 'Passwords does not match.';
		return await this.setPassword(userId, newPassword);
	}

	// With a givan userId, change directly to newPassword (usefull for admins, for example)
	async setPassword(userId: string | number, newPassword: string) {
		let password = await bcrypt.hash(newPassword, SALT);
		let updated = await this.userRepository.update(userId, { password })
		console.log("updated", updated)
		return updated;
	}
}

class MailAttachments {
	path: string
	cid: string
	fileName?: string
}