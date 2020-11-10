import { Module } from "@nestjs/common";
import { NodeMailerService as MailService } from "./MailService";

@Module({
    providers: [MailService],
    exports: [MailService]
})
export class NodeMailerModule { }