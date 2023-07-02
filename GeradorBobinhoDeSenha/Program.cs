using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    public static string CriptografarSenha(string senha, string chave)
    {
        byte[] senhaBytes = Encoding.UTF8.GetBytes(senha);
        using (Aes aes = Aes.Create())
        {
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(chave, aes.IV, 10000);
            aes.Key = pbkdf2.GetBytes(32);
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (MemoryStream ms = new MemoryStream())
            {
                ms.Write(aes.IV, 0, aes.IV.Length);
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(senhaBytes, 0, senhaBytes.Length);
                    cs.Close();
                }
                byte[] senhaCriptografadaBytes = ms.ToArray();
                return Convert.ToBase64String(senhaCriptografadaBytes);
            }
        }
    }

    public static string DescriptografarSenha(string senhaCriptografada, string chave)
    {
        try
        {
            byte[] senhaCriptografadaBytes = Convert.FromBase64String(senhaCriptografada);
            using (Aes aes = Aes.Create())
            {
                Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(chave, senhaCriptografadaBytes.Take(16).ToArray(), 10000);
                aes.Key = pbkdf2.GetBytes(32);
                aes.IV = senhaCriptografadaBytes.Take(16).ToArray();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (MemoryStream ms = new MemoryStream(senhaCriptografadaBytes, 16, senhaCriptografadaBytes.Length - 16))
                {
                    using (MemoryStream decryptedMs = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                        {
                            cs.CopyTo(decryptedMs);
                        }
                        byte[] senhaDescriptografadaBytes = decryptedMs.ToArray();
                        return Encoding.UTF8.GetString(senhaDescriptografadaBytes);
                    }
                }
            }
        }
        catch (Exception)
        {
            return "Errou feio palhaço! Some Daqui!";
        }
    }



    static void Main()
    {
        Console.Write("Escolhe uma senha qualquer: ");
        string senha = Console.ReadLine();

        Console.Write("Digite uma chave para criptografar a senha: ");
        string chave = Console.ReadLine();

        string senhaCriptografada = CriptografarSenha(senha, chave);
        Console.WriteLine("Senha criptografada: " + senhaCriptografada);

        Console.WriteLine("--- Descriptografando a senha ---");

        Console.Write("Digite a chave de descriptografia: ");
        string chaveDescriptografia = Console.ReadLine();

        string senhaDescriptografada = DescriptografarSenha(senhaCriptografada, chaveDescriptografia);
        Console.WriteLine("Senha descriptografada: " + senhaDescriptografada);
    }
}
