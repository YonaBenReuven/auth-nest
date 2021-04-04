import { SetMetadata } from '@nestjs/common';

export const UserField = (userField: string) => SetMetadata('userField', userField);