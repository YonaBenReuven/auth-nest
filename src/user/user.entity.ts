import { Entity, TableInheritance, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, OneToMany } from 'typeorm';

import { UserRole } from 'src/user-role/user-role.entity';

@Entity()
@TableInheritance({ column: { type: "varchar", name: "type" } })
export class User {

	@PrimaryGeneratedColumn('uuid')
	id: number;

	@Column()
	username: string;

	@Column()
	password: string;

	@CreateDateColumn()
	created: Date;

	@UpdateDateColumn()
	updated: Date;

	@OneToMany(type => UserRole, userRole => userRole.user)
	userRoles: UserRole[];
}