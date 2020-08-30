import { ChildEntity, Column } from 'typeorm';

import { User } from 'src/user/user.entity';

@ChildEntity()
export class Admin extends User {
	@Column()
	adminName: string;
}