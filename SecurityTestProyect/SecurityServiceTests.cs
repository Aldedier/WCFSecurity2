using WCFSecurity;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;

namespace WCFSecurity.Tests
{
    [TestClass()]
    public class SecurityServiceTests
    {
        SecurityService security = new SecurityService();
        const string key = "";

        [TestMethod()]
        public void GetTokenTest()
        {
            var passwordHash =
                new Common().Encrypt("Visual001", "1Z0NteBR1EdCWkfyIUuGyg==");
            var token = security.GetToken("Aldedier", passwordHash);
            System.Diagnostics.Debug.WriteLine(token);

            Assert.IsTrue(!string.IsNullOrEmpty(token));
        }



        [TestMethod()]
        public void ValidateTokenTest()
        {
            try
            {
                TokenSecurityModel token = security.ValidateToken();
                Assert.IsNotNull(token);
            }
            catch (System.Exception ex)
            {
                Debug.WriteLine(ex.Message);
                Assert.Fail(ex.Message);
            }
        }
    }
}