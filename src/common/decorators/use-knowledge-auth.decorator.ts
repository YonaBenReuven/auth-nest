import { KnowledgeAuthGuard } from '../guards/knowledge-auth.guard';
import { createAuthDecorator } from '../functions/create-auth-decorator.function';

export const UseKnowledgeAuth = createAuthDecorator(KnowledgeAuthGuard);