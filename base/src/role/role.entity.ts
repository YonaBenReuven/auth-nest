import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity()
export class Role {

	@PrimaryGeneratedColumn()
	id!: number;

	@Column({ length: 20 })
	name!: string;

	@Column()
	description!: string;
}