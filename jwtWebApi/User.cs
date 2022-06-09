namespace jwtWebApi
{
    public class User
    {
        public string UserName { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; } // tạo  băm mk 
        public byte[] PasswordSalt { get; set; } // sắp xếp mk 
    }
}
