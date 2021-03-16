
import { User } from '../user/user.entity';
import { Entity, Column, PrimaryGeneratedColumn, JoinColumn, ManyToOne } from 'typeorm';
// import { User } from '../user/user.entity';


@Entity()
export class AccessLogger {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column()
  date: Date;

  @ManyToOne
    (() => User, user => user.id)
  @JoinColumn()
  user: User;

  @Column()
  success: boolean
}