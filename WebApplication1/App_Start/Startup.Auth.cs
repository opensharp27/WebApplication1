using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin.Security.Providers.Yahoo;
using Owin;
using WebApplication1.Models;

namespace WebApplication1
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });            
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            app.UseTwitterAuthentication(new Microsoft.Owin.Security.Twitter.TwitterAuthenticationOptions
            {
                ConsumerKey = "wjoRLZz08oRVh0eUTQRsLdHx4",
                ConsumerSecret = "CKH9b9p7Sp23xWRbwKq4ndVt9ux185PC5zIBHXfAcrPUFNtZz7",
                BackchannelCertificateValidator = new Microsoft.Owin.Security.CertificateSubjectKeyIdentifierValidator(new[]
                {
                    "A5EF0B11CEC04103A34A659048B21CE0572D7D47", // VeriSign Class 3 Secure Server CA - G2
                    "0D445C165344C1827E1D20AB25F40163D8BE79A5", // VeriSign Class 3 Secure Server CA - G3
                    "7FD365A7C2DDECBBF03009F34339FA02AF333133", // VeriSign Class 3 Public Primary Certification Authority - G5
                    "39A55D933676616E73A761DFA16A7E59CDE66FAD", // Symantec Class 3 Secure Server CA - G4
                    "‎add53f6680fe66e383cbac3e60922e3b4c412bed", // Symantec Class 3 EV SSL CA - G3
                    "4eb6d578499b1ccf5f581ead56be3d9b6744a5e5", // VeriSign Class 3 Primary CA - G5
                    "5168FF90AF0207753CCCD9656462A212B859723B", // DigiCert SHA2 High Assurance Server C‎A 
                    "B13EC36903F8BF4701D498261A0802EF63642BC3" // DigiCert High Assurance EV Root CA
                })
            });

            app.UseFacebookAuthentication(
                appId: "750116155146163",
                appSecret: "0a92f94be1df55fc3a71ceaf507156d2"
            );

            app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = "398924250366-6mm31kcs1ejut87jvof6q20isosuqhn1.apps.googleusercontent.com",
                ClientSecret = "W2VZejZP4I-RQi2AC0pobpG-"
            });

            app.UseYahooAuthentication(new YahooAuthenticationOptions()
            {
                ConsumerKey = "dj0yJmk9M0RLV1pLWnF2TU1VJmQ9WVdrOWFsRllRa0Z2TlRnbWNHbzlNQS0tJnM9Y29uc3VtZXJzZWNyZXQmeD05Zg--",
                ConsumerSecret = "3aaf3d797e872fabbbb1503b0394695bc62e89de"
            });
        }

        partial class KeySecret
        {
            void GetConfigValue(String key)
            {
                String[] values = System.Configuration.ConfigurationManager.AppSettings[key].Split(';');

                Key = values[0];
                Secret = values[1];
            }

            public KeySecret (String key) {
                GetConfigValue(key);
            }

            public String Key { get; set; }
            public String Secret { get; set; }
        }
    }
}