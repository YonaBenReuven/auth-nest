import { Test, TestingModule } from '@nestjs/testing';
import { EmailUserService } from './email-user.service';

describe('EmailUserService', () => {
  let service: EmailUserService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [EmailUserService],
    }).compile();

    service = module.get<EmailUserService>(EmailUserService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
