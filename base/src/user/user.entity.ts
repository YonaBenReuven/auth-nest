import { Entity, TableInheritance, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToMany, JoinTable, BeforeInsert } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { Role } from '../role/role.entity';
import { SALT } from '../common/constants';

@Entity()
@TableInheritance({ column: { type: "varchar", name: "type" } })
export class User {

	@PrimaryGeneratedColumn('uuid')
	id!: string;

	@Column()
	username!: string;

	@Column({ select: false })
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
		this.password = await bcrypt.hash(this.password, SALT);
	}
}