"""
    email notification class
"""
import os
import smtplib
from pathlib import Path
from email.message import EmailMessage
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import COMMASPACE, formatdate
from email.mime.base import MIMEBase
from email import encoders

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class EmailNotification:
    """
        Email Notification Support Class
    """
    def __init__(self, logger):
        """
            constructor
            Logger - Logger file
        """
        try:            
            self.logger = logger
        except Exception as e:
            raise Exception("Error while initaiting email object..." , e)

    def send_mail(self,to_email, send_from,resetcode,username):
        """
        Send Email Function[accepts multiple attachments]
            environment: LOCAL --> allows local debug
            subject: Configuration file name
            body: Mail Body
            to_email: recipient email address
            log_file_path: List of attachment paths]
            send_from: sender email address
        return: None
        """
        try:
            # Email configuration
            sender_email = send_from
            receiver_email =to_email
            subject = "Password Reset Instructions"
            email_body = self.email_template()
            email_body=email_body.replace("{{resetcode}}",resetcode)
            email_body=email_body.replace("{{user}}",username)


            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = receiver_email
            msg['Subject'] = subject 
            replyemail="DHEC OCRM Team <DONOTREPLY@dhec.sc.ogov>"
            msg.add_header("Reply-To",replyemail)
            msg.attach(MIMEText(email_body, 'HTML'))

            server = smtplib.SMTP('publicsmtp-new.dhec.sc.gov',25)

            text = msg.as_string()
            server.sendmail(send_from, to_email, text)
            server.quit() 
        except Exception as e:
            if (self.logger != None):
                self.logger.printErrorMessage('Sending email failed! -' +str(e))
            return 1, None
        
        

    def send_mail_wt_attachment(self, environment, subject, body, to_email, log_file_path, send_from,attachment_file=""):
        """
        Send Email Function [accepts a single attachment]
            environment: LOCAL --> allows local debug
            subject: Configuration file name
            body: Mail Body
            to_email: recipient email address
            log_file_path: Log File Path
            send_from: sender email address
        return: None
        """
        try:
            msg=EmailMessage()
            msg['From'] = send_from
            msg['To'] = to_email
            msg['Date'] = formatdate(localtime=True)
            msg['Subject'] = environment + " : " + subject
            
            content = body
            msg.set_content(content)
            
            if attachment_file!="":
                createpath=Path(attachment_file)
                if createpath.is_file():
                    file_name=createpath.name
            
                    with open(createpath,"rb") as myfile:
                        data=myfile.read()
                        msg.add_attachment(data,maintype="application",subtype="",filename=file_name)

            server = smtplib.SMTP('publicsmtp.dhec.sc.gov',25)

            text = msg.as_string()
            server.sendmail(send_from, to_email, text)
            server.quit()

        except Exception as e:
            if (self.logger != None):
                self.logger.printErrorMessage('Sending email failed! -' +str(e))
            return 1, None              


    def send_mail_without_attachment(self, environment, subject, body, to_email, log_file_path, send_from):
        """
        Send Email Function[accepts multiple attachments]
            environment: LOCAL --> allows local debug
            subject: Configuration file name
            body: Mail Body
            to_email: recipient email address
            log_file_path: List of attachment paths]
            send_from: sender email address
        return: None
        """
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = send_from
            msg['To'] = to_email
            # msg['To'] = COMMASPACE.join(to_email)
            msg['Date'] = formatdate(localtime=True)
            msg['Subject'] = environment + " : " + subject
            
            content = MIMEText(body, 'html')
            msg.attach(content)
   

            for path in log_file_path:
                attachment = open(path, "rb") 
        
                p = MIMEBase('application', 'octet-stream') 
        
                p.set_payload((attachment).read()) 
        
                encoders.encode_base64(p) 
                
                p.add_header('Content-Disposition', "attachment; filename= %s" % os.path.basename(path)) 
                msg.attach(p) 
            server='publicsmtp.dhec.sc.gov'
            server = smtplib.SMTP('publicsmtp.dhec.sc.gov',25)

            text = msg.as_string()
            server.sendmail(send_from, to_email, text)
            server.quit()
        except Exception as e:
            print(str(e))
            
            
            
  
    def send_gmail(self,to_email, send_from,resetcode,username,smtp_password):
        """
            Send Email Function[accepts multiple attachments]
                subject: Configuration file name
                body: Mail Body
                to_email: recipient email address
                send_from: sender email address
            return: None
        """
        try:
            # Email configuration
            sender_email = send_from
            receiver_email =to_email
            subject = "Password Reset Instructions"
            email_body = self.email_template()
            email_body=email_body.replace("{{resetcode}}",resetcode)
            email_body=email_body.replace("{{user}}",username)

            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = receiver_email
            msg['Subject'] = subject 
            replyemail="DHEC OCRM Team <DONOTREPLY@dhec.sc.ogov>"
            msg.add_header("Reply-To",replyemail)
            msg.attach(MIMEText(email_body, 'HTML'))

            # Connect to the SMTP server
            smtp_server = "smtp.gmail.com"
            smtp_port = 587  # Or 465 for SSL
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()  # Use TLS for security
            server.login(sender_email, smtp_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            server.quit()         
        except Exception as e:
            print(str(e))


    def email_template(self):
        try:
            return """<!DOCTYPE html><body>
                    <p>Dear {{user}},</p>
                    <table>
                        <tbody>
                            <tr>
                                <td>You requested to reset your password. Use the reset code below to reset your password.</td>
                            </tr>
                            <tr>
                                <td style="font-size: 20px; font-weight: bold;color: blue; letter-spacing:5px">{{resetcode}}</td>
                            </tr>
                        <tr>
                            <td>This reset code will expire in 10 minutes</td>
                        </tr>
                        <tr>
                            <td>Submit this code, together with other requested information on the DHEC webpage to change your password.</td>
                        </tr>
                            <tr>
                                <td>&nbsp;</td>
                            </tr>
                            <tr>
                                <td>If you didn't request to reset your password, please ignore this email. Your password won't change until you submit this reset code.</td>
                            </tr>
                            <tr>
                                <td>&nbsp;</td>
                            </tr>
                        </tbody>
                    </table>
                    <hr>
                    <p>Thank you.</p>
                    <p>SCDHEC - OCRM Team</p>
                </body>"""
        except Exception as e:
            print(str(e))

 

 

 

 


                

                

    
 