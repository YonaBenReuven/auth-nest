export interface MailerInterface {
    send(
        data: {
            from: string,
            to: string | Array<string>,
            html: string,
            text?: string,
            subject: string,
            attachments?: Array<MailAttachments>
        },
        cb?: Function
    ): any
}


export class MailAttachments {
    path: string
    cid: string
    fileName?: string
}