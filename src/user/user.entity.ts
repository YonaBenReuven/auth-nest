import { Entity, TableInheritance, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToMany, JoinTable, BeforeInsert, BeforeUpdate } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { Role } from 'src/role/role.entity';
import { SALT } from 'src/common/constants';

@Entity()
@TableInheritance({ column: { type: "varchar", name: "type" } })
export class User {

	@PrimaryGeneratedColumn('uuid')
	id: string;

	@Column()
	username: string;

	@Column({ select: false })
	password: string;

	@CreateDateColumn()
	created: Date;

	@UpdateDateColumn()
	updated: Date;

	@Column({ select: false })
	type: string;

	@ManyToMany(type => Role)
	@JoinTable({ name: 'user_role' })
	roles: Role[];

	@BeforeInsert()
	async hashPassword() {
		this.password = await bcrypt.hash(this.password, SALT);
	}
}