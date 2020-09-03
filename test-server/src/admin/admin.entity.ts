import { ChildEntity, Column } from 'typeorm';
import { User } from '@hilma/auth-nest';

@ChildEntity()
export class Admin extends User {
	@Column()
	adminName: string;
}