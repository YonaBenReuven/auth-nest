import { SetMetadata } from '@nestjs/common';

import { User } from '../../user/user.entity';

export const Entities = <T extends Array<typeof User>>(...entities: T) => SetMetadata('entities', entities);
