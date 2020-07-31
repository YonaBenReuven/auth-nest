import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from 'typeorm';

import { UserRole } from 'src/user-role/user-role.entity';

@Entity()
export class Role {

	@PrimaryGeneratedColumn()
	id: number;

	@Column({ length: 20 })
	name: string;

	@Column()
	description: string;

	@OneToMany(type => UserRole, userRole => userRole.user)
	userRole: UserRole;
}