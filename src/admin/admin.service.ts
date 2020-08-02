import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Admin } from './admin.entity';
import { Repository } from 'typeorm';

@Injectable()
export class AdminService {
	constructor(
		@InjectRepository(Admin)
		private readonly adminRepository: Repository<Admin>
	) { }

	createAdmin(admin: Admin) {
		return this.adminRepository.save(admin);
	}
}
