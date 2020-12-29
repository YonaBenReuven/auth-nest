import { BeforeInsert, Column, Entity, JoinColumn, OneToOne, PrimaryGeneratedColumn } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { User } from '../user/user.entity';
import { SALT } from '../common/constants';

@Entity('two_factor')
export class TwoFactor {
	@PrimaryGeneratedColumn()
	id: number;

	@Column({ name: 'code', type: 'varchar', length: '255', nullable: true, default: null })
	code?: string;

	@Column({ name: 'attempt', type: 'tinyint', unsigned: true, nullable: false, default: 0 })
	attempt: number;

	@Column({ name: 'code_created_date', type: 'timestamp', precision: 6, nullable: true, default: null })
	codeCreatedDate?: Date;

	@Column({ name: 'user_blocked_date', type: 'timestamp', precision: 6, nullable: true, default: null })
	userBlockedDate?: Date;

	@Column({ name: 'user_id', type: 'varchar', length: '36', nullable: false })
	userId: string;

	@OneToOne(type => User)
	@JoinColumn({ name: 'user_id' })
	user: User;

	@BeforeInsert()
	async hashPassword() {
		if (this.code) this.code = await bcrypt.hash(this.code, SALT);
	}
}