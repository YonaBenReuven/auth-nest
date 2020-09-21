import { Entity, TableInheritance, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToMany, JoinTable, BeforeInsert } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { Role } from '../role/role.entity';
import { SALT } from '../common/constants';

@Entity()
@TableInheritance({ column: { type: "varchar", name: "type" } })
export class User {

	constructor(basicUser: Partial<User> = {}) {
		basicUser.username && (this.username = basicUser.username);
		basicUser.password && (this.password = basicUser.password);
		if (basicUser.roles && basicUser.roles.length) this.roles = basicUser.roles;
	}

	@PrimaryGeneratedColumn('uuid')
	id!: string;

	@Column()
	username!: string;

	@Column({ select: false, default: null })
	password!: string;

	@CreateDateColumn()
	created!: Date;

	@UpdateDateColumn()
	updated!: Date;

	@Column({ select: false })
	type!: string;

	@ManyToMany(_type => Role)
	@JoinTable({ name: 'user_role' })
	roles!: Role[];

	@BeforeInsert()
	async hashPassword() {
		if (this.password)
			this.password = await bcrypt.hash(this.password, SALT);
	}
}
