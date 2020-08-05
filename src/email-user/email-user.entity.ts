import { ChildEntity, Column } from 'typeorm';
import { User } from 'src/user/user.entity';

@ChildEntity()
export class EmailUser extends User {

    @Column({ default: 0 })
    emailVerified: boolean

    @Column({ nullable: true, length: 150 })
    verificationToken: string
}