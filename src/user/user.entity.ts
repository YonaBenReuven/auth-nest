import { Entity, TableInheritance, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToMany, JoinTable, BeforeInsert } from 'typeorm';

import { Role } from 'src/role/role.entity';

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

	@ManyToMany(type => Role)
	@JoinTable()
	roles: Role[];
}