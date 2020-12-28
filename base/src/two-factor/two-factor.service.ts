import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';
import { Request, Response } from 'express';
import * as https from 'https';
import * as parser from 'xml2js';
import * as bcrypt from 'bcrypt';

import { AuthConfigTwoFactorSecretOrKey, AuthConfigTwoFactorTokenCookie } from '../common/interfaces/auth-config.interface';
import { jwtConstants, SALT, TWO_FACTOR_OPTIONS, TWO_FACTOR_TOKEN } from '../common/constants';
import { TwoFactorOptions } from '../common/interfaces/two-factor-options.interface';
import { RequestUserType } from '../common/interfaces/request-user-type.interface';
import { User } from '../user/user.entity';

import { TwoFactor } from './two-factor.entity';
import { LoginErrorCodes } from 'src/common/loginErrorCodes';

@Injectable()
export class TwoFactorService {
	private twoFactorSecretOrKey: string;

	private twoFactorTokenCookie: string;

	constructor(
		@Inject(TWO_FACTOR_OPTIONS)
		private readonly twoFactorOptions: Required<TwoFactorOptions>,
		@InjectRepository(TwoFactor)
		private readonly twoFactorRepository: Repository<TwoFactor>,
		@InjectRepository(User)
		private readonly userRepository: Repository<User>,
		private readonly configService: ConfigService,
		private readonly jwtService: JwtService
	) {
		this.twoFactorSecretOrKey = this.configService.get<AuthConfigTwoFactorSecretOrKey>('auth.twoFactorSecretOrKey') ?? jwtConstants.twoFactorSecret;
		this.twoFactorTokenCookie = this.configService.get<AuthConfigTwoFactorTokenCookie>('auth.twoFactorToken_cookie') ?? TWO_FACTOR_TOKEN;
	}
	/**
	 * 
	 * @param phone The phone number you would like to send an SMS to
	 * @param text The SMS content
	 * @param senderName The sender's name
	 */
	sendSMS(phone: string, text: string, senderName = "Hilma"): Promise<any> {
		phone = '972' + phone.substring(1);

		return new Promise<any>((resolve, reject) => {
			const encodedText = encodeURIComponent(text);

			const data = `<?xml version="1.0" encoding="UTF-8"?><sms><user><username>Fb9KF2fX</username><password>RX70n5eE</password></user><source>${senderName}</source><destinations><phone>${phone}</phone></destinations><message>${encodedText}</message><response>0</response></sms>`;

			const options = {
				hostname: 'www.019sms.co.il',
				port: 443,
				path: '/api',
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Content-Length': data.length
				}
			};

			const req = https.request(options, res => {
				let data = "";

				res.on('data', chunk => {
					data += chunk;
				});

				res.on('end', () => {
					parser.parseString(data, (err, result) => {
						if (err) {
							console.error(err);
							return reject(err);
						}
						if (!result || !result.sms || !result.sms.status || result.sms.status[0] !== '0') {
							console.error(result);
							return reject(result);
						}

						return resolve(result);
					});
				});
			});

			req.on('error', error => {
				console.error(error);
				return reject(error);
			});

			req.write(data);
			req.end();
		});
	}
	/**
	 * Creates a code with a certain length
	 * @param length the length of the code. Defaults to the codeLength in twoFactorOptions
	 */
	createCode(length = this.twoFactorOptions.codeLength): string {
		return Array.from({ length }).map(() => Math.floor(Math.random() * 10)).join('');
	}
	/**
	 * Checks if a user's blocked date has ended
	 * @param userBlockedDate The date a user was blocked
	 */
	isBlocked(userBlockedDate: Date | undefined): boolean {
		if (!userBlockedDate) return false;

		const now = new Date();

		const dateDiff = now.getTime() - userBlockedDate.getTime();

		return dateDiff < this.twoFactorOptions.blocked * 1000;
	}
	/**
	 * Checks if a user's number of attempts has surpassed max attempts
	 * @param attempt A user's number of attempts
	 */
	isMaxAttempts(attempt: number, orEqual = true) {
		return orEqual ? attempt >= this.twoFactorOptions.maxAttempts : attempt > this.twoFactorOptions.maxAttempts;
	}
	/**
	 * Checks if a user's code has expired
	 * @param codeCreatedDate The date a code was created
	 */
	codeHasExpired(codeCreatedDate: Date) {
		const now = new Date();

		const dateDiff = now.getTime() - codeCreatedDate.getTime();

		return dateDiff >= this.twoFactorOptions.expires * 1000;
	}
	/**
	 * Creates a default string of an SMS with a code
	 * @param code The code
	 */
	SMSGenerator(code: string) {
		return `קוד האימות הוא: ${code}`;
	}
	/**
	 * Blocks user
	 * @param twoFactorId two factor id
	 */
	blockUser(twoFactorId: number) {
		return this.twoFactorRepository.update(twoFactorId, { userBlockedDate: new Date(), attempt: 0 });
	}
	/**
	 * Increments a user's attempt
	 * @param twoFactorId two factor id
	 */
	incrementAttempt(twoFactorId: number) {
		return this.twoFactorRepository
			.createQueryBuilder('twoFactor')
			.update()
			.set({ attempt: () => 'attempt + 1' })
			.whereInIds([twoFactorId])
			.execute();
	}
	/**
	 * Validates a user by checking if the user is blocked or has surpassed max attempts
	 * @param userId The user's id
	 */
	async validateUser(userId: string) {
		let twoFactor = await this.twoFactorRepository
			.createQueryBuilder('twoFactor')
			.select(['twoFactor.id', 'twoFactor.attempt', 'twoFactor.userBlockedDate'])
			.where('twoFactor.userId = :userId', { userId })
			.getOne();

		twoFactor ??= await this.twoFactorRepository.save(this.twoFactorRepository.create({ userId }));

		const isBlocked = this.isBlocked(twoFactor.userBlockedDate);

		if (isBlocked) {
			throw LoginErrorCodes.UserIsBlocked;
		}

		const isMaxAttempts = this.isMaxAttempts(twoFactor.attempt);

		if (isMaxAttempts) {
			await this.blockUser(twoFactor.id);
			throw LoginErrorCodes.MaxAttempts;
		}
	}
	/**
	 * Function that sends a code to a user
	 * @param user The request user
	 * @param res The express res object
	 * @param sendInDevelopment Should send sms in development (default to twoFactorOptions)
	 * @param sendInProduction Should send sms in production (default to twoFactorOptions)
	 * @param SMSGenerator Function that generates an SMS message (default to `קוד האימות הוא: ${code}`)
	 * @param code The code to send to the user
	 */
	async sendCode(
		user: RequestUserType,
		res: Response,
		sendInDevelopment = this.twoFactorOptions.sendInProduction,
		sendInProduction = this.twoFactorOptions.sendInProduction,
		SMSGenerator = this.SMSGenerator,
		code = this.createCode()
	) {
		let phone = user[this.twoFactorOptions.phoneField];

		if (!phone) {
			const { [this.twoFactorOptions.phoneField as keyof User]: phoneValue } = await this.userRepository
				.createQueryBuilder('user')
				.select([`user.${this.twoFactorOptions.phoneField}`])
				.whereInIds([user.id])
				.getOne();

			phone = phoneValue;
		}

		const NODE_ENV = process.env.NODE_ENV || 'development';

		if (
			(NODE_ENV === 'production' && sendInProduction) ||
			(NODE_ENV !== 'production' && sendInDevelopment)
		) {
			await this.sendSMS(phone, SMSGenerator(code), this.twoFactorOptions.SMSSender);
		}

		const hashedCode = await bcrypt.hash(code, SALT);

		await this.twoFactorRepository
			.createQueryBuilder('twoFactor')
			.update()
			.set({
				attempt: () => 'attempt + 1',
				code: hashedCode,
				codeCreatedDate: new Date(),
			})
			.where('twoFactor.userId = :userId', { userId: user.id })
			.execute();

		const requestUser: RequestUserType = {
			id: user.id,
			username: user.username,
			type: user.type,
			roles: user.roles,
			roleKeys: user.roleKeys
		}

		const twoFactorToken = this.jwtService.sign(requestUser, {
			expiresIn: this.twoFactorOptions.expires,
			secret: this.twoFactorSecretOrKey
		});

		res.cookie(this.twoFactorTokenCookie, twoFactorToken, { maxAge: this.twoFactorOptions.expires * 1000 });

		const body = {
			id: user.id,
			username: user.username,
			[this.twoFactorTokenCookie]: twoFactorToken
		};

		return body;
	}
	async validateCode(userId: string, code: string) {
		const twoFactor = await this.twoFactorRepository
			.createQueryBuilder('twoFactor')
			.select(['twoFactor.id', 'twoFactor.code', 'twoFactor.attempt', 'twoFactor.codeCreatedDate', 'twoFactor.userBlockedDate',])
			.where('twoFactor.userId = :userId', { userId })
			.getOne();

		if (!twoFactor) throw 'No twoFactor instance';

		const isBlocked = this.isBlocked(twoFactor.userBlockedDate);

		if (isBlocked) {
			throw LoginErrorCodes.UserIsBlocked;
		}

		const isMaxAttempts = this.isMaxAttempts(twoFactor.attempt, false);

		if (isMaxAttempts) {
			await this.blockUser(twoFactor.id);
			throw LoginErrorCodes.MaxAttempts;
		}

		const codeHasExpired = this.codeHasExpired(twoFactor.codeCreatedDate);

		if (codeHasExpired) {
			await this.incrementAttempt(twoFactor.id);
			throw LoginErrorCodes.CodeHasExpired;
		}

		if (!bcrypt.compareSync(code, twoFactor.code)) {
			await this.incrementAttempt(twoFactor.id);
			throw LoginErrorCodes.IncorrectCode;
		}

		await this.twoFactorRepository
			.createQueryBuilder('twoFactor')
			.update()
			.set({
				code: null,
				attempt: 0,
				codeCreatedDate: null,
				userBlockedDate: null
			})
			.whereInIds([twoFactor.id])
			.execute();
	}
}
