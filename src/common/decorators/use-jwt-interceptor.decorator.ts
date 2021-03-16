import { UseInterceptors } from '@nestjs/common';

import { JwtAuthInterceptor } from '../interceptors/jwt-auth.interceptor';

export const UseJwtInterceptor = () => UseInterceptors(JwtAuthInterceptor);