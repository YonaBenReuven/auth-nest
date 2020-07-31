import { Entity, PrimaryColumn, ManyToOne } from 'typeorm';

import { User } from 'src/user/user.entity';
import { Role } from 'src/role/role.entity';

@Entity()
export class UserRole {
	
	@PrimaryColumn()
	userId: string;

	@PrimaryColumn()
	roleId: number;

	@ManyToOne(type => User, user => user.userRole)
	user: User;

	@ManyToOne(type => Role, role => role.userRole)
	role: Role;
}