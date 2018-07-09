using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.ServiceModel.Web;
using System.Text;
using System.Web;

namespace WCFSecurity
{
    public class SecurityService : Security
    {
        DbSecurityEntities db = new DbSecurityEntities();

        public ResponseModel AddRole(string username, string role)
        {
            throw new NotImplementedException();
        }

        public ResponseModel changePassword(string username, string actualPassword, string newPassword)
        {
            throw new NotImplementedException();
        }

        public ResponseModel CreateUser(string username, string password)
        {
            throw new NotImplementedException();
        }


        public TokenSecurityModel ValidateToken()
        {
            var requestToken = "R1lXbnJmTit5QTFITGdVWmJTUnRwMUFCTTVMWHVGNzAwTkZoUHZFVi9lNTRiME9BZFgxWi9JUVF5eXpsL0YrK3Q4U00vU1V2YUdzVEs4c25VVVlsYVZtcmRzRmxPZ0c1NXZTYUR0NWdDYkRCUXRhY3g1Ty95dWUyV2F2bnQvVTJ6eUx4QytwY2NzNURXeHFNb0JpL1FUMkZObHREZC9yYkRyUEdsb2dZVzkyNGR6TW11V2o5MVhRVSswV2VKU1M2YU9Mb0xEREM3emVYSXoxVVAvdWNFeERCdDQ1VEVNZlRGRDhrN3k5MTcycEVUdmY5cWdKdEhuUERHTjMrdVhheQ=="; //HttpContext.Current.Request["__TOKEN_SECURITY__"];
            if (string.IsNullOrEmpty(requestToken))
                throw new Exception("Token invalido");

            byte[] tokenBytes = Convert.FromBase64String(requestToken);
            string tokenUTF8 = Encoding.UTF8.GetString(tokenBytes);
            string tokenJSON = new Common().Decript(tokenUTF8, key);
            TokenSecurityModel tokenSecurityModel = JsonConvert.DeserializeObject<TokenSecurityModel>(tokenJSON);

            if (tokenSecurityModel == null)
                throw new Exception("Token invalido");

            if (tokenSecurityModel.Expiration <= DateTime.Now)
                throw new Exception("Token expirado");

            return tokenSecurityModel;
        }



        const string key = "1Z0NteBR1EdCWkfyIUuGyg==";
        public string GetToken(string username, string password)
        {

            var common = new Common();
            var passwordResult = common.Decript(password, key);

            var passwordSHA256 = common.GenerateSHA256(passwordResult);

            var user = db.User.FirstOrDefault(x => x.Username == username &&
            x.Password == passwordSHA256);

            if (user == null) return "Credenciales no validas !!!!";

            var roles = db.UsersInRoles.Where(x => x.User.UserId == user.UserId)
                .Select(x => x.Role.Name).ToArray();

            var token = new TokenSecurityModel
            {
                DisplayName = string.Concat("Mr ", user.Username),
                Expiration = DateTime.Now.AddMinutes(1),
                Username = username,
                Roles = roles,
                id = Guid.NewGuid()
            };

            var tokenString = JsonConvert.SerializeObject(token);
            var tokenBytes = Encoding.UTF8.GetBytes(common.Encrypt(tokenString, key));

            return Convert.ToBase64String(tokenBytes);

        }
    }
}
