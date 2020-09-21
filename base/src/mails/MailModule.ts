import { Module } from "@nestjs/common";
import { NodeMailerService } from "./MailService";

@Module({
    providers: [NodeMailerService],
    exports: [NodeMailerService]
})
export class NodeMailerModule { }