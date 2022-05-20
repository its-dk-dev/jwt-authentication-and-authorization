using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Authorization;
using JWTAuthenticationAndAuthorization.authentication;

namespace JWTAuthenticationAndAuthorization.Controllers
{
    [Route("api/AdminTenantApi")]
    [ApiController]
    public class AdminTenantApiController : ControllerBase
    {
        [Authorize()]
        [Route("~/api/getAllUserDetails")]
        [HttpGet]
        public HttpResponseMessage getAllUserDetails()
        {
            HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.BadRequest);
            return response;
        }

        [Authorize(Roles = UserRoles.SuperAdmin)]
        [Route("~/api/getAllVendorDetails")]
        [HttpGet]
        public HttpResponseMessage getAllVendorDetails()
        {
            HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.BadRequest);
            return response;
        }

        [Authorize(Roles = UserRoles.Vendor)]
        [Route("~/api/getVendorDetails")]
        [HttpGet]
        public HttpResponseMessage getVendorDetails()
        {
            HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.BadRequest);
            return response;
        }
    }
}
