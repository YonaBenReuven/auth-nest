import { env } from 'process'
import { config } from 'dotenv';
config();
export const VerifyMailTemplate = `
<div style={{ direction: 'rtl' }}><h1>ברוכים הבאים ל{{sitename}}!</h1>
<p>נשאר רק עוד צעד קטן כדי לסיים את ההרשמה שלכם!</p>
<p>לחצו על הקישור <a href="${env.REACT_APP_DOMAIN}/api{{verifyPath}}?token={{token}}">כאן</a> כדי לאמת את כתובת המייל💚</p>
{{{placeForLogo}}}
</div>`

export const ResetPasswordTemplate = `<div style={{ direction: 'rtl' }}><h3> איפוס סיסמה באתר {{sitename}}!</h3>
<p>היי, ביקשתם לשנות את הסיסמה </p>
<p>לחצו על הקישור <a href="${env.REACT_APP_DOMAIN}/api{{changePath}}?token={{token}}&email={{email}}">כאן</a> כדי לשנות את הסיסמה שלכם למערכת🔒</p>
{{{placeForLogo}}}
</div>`

