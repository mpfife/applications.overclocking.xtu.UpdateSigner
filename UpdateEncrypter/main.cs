using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
/*
using System.Data;
using System.Xml.Linq;
using System.Security.Cryptography;
using System.Security.AccessControl;

using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
*/


namespace UpdateEncrypter
{
    public class EntryPoint
    {
        const int MajorVersion = 0;
        const int MinorVersion = 9;

        const string FullRSAKeyFilename = "\\fullkey.xml";
        const string PublicRSAKeyFilename = "\\pubkey.xml";
        const string SignedOutputFilename = "\\signed.xml";

        // This key should be embedded in the XTU application. They key is public and the world can see it.
        //const string staticPublicKey = "<RSAKeyValue><Modulus>whXjHYXgZwWnGOzt4e+gD22fj5sfI13gtiECNXGDXWJYdUWI6aveaOcMyqrKRI0hSnHNZLsX92+Drx2M4Zr9534fEmoLecASyl1ajIE612i1J98tCMT3hFhBQL3KaOoBUuDPLpfzeigOk57LakzFHlxWc2KduJU/NBe4Mo1UNnU=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        const string staticPublicKey = "<RSAKeyValue><Modulus>xunwmXI2wU2el4vEg7LcNlNaaiocE+pe4AtES+89h30LP/D4zdYcVt8LvmwaS10XFc7IEDjgWqxziFXqNx8VCllEPhWeuhm0GQPMqQW9M0qS3XLG5fBzfKbqzswU4WLHJOdAdcNdhOw35tW+lQFS/5Bzl+N8HVldvwMxQ3bYmaEQslLDNixe2bfjQtBpE1HS6+6VDtLuLfaOEEX/MGa3CFJRT+qHgcNDzl+HxbojBSyMwEc8XEZrgXJ85yX5LgCQ8SvpSf148N+xs+lww8ntsI1x8KtCUqfnT4lfdxdq2PdRiYPR8honEc2VZeJS2o+Mn0O5LqD+eA5wzGOYod8wn0GTifAjUUTmoyj8RZxyvfCsxbFq9ImYqmHwakDhOaQgCDBfSQjfCGMZTANCcTaikGWP/wIg6Yk1H3HJforrlR2/Sn8fxqfB59GhtK2noYTc6ASPr/lq7isG2UURFY8IYebr//8LLSHcCYfD6tqAHp9BgmO18hBQnWqUCAMAYVTt9KQpF2yjnGa9S4nY9T2B0YxuUMPSq+EpFjCfLALxxXMfjY5PcFitMvS11o0pEQ3P+OnwjqPiVkvfjNDVwkHxGXarAqXdIqUi2dHzpsl8Y3KjfUgMz4/e+TNDV69JVR9dEfy+16RTma6p7KNwiOtl82b4tcSX/QMQk2O9w4x/NGU=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        // Sign an XML file.
        // This document cannot be verified unless the verifying
        // code has the key with which it was signed.
        //https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-sign-xml-documents-with-digital-signatures
        public static void SignXml(XmlDocument xmlDoc, RSA rsaKey)
        {
            // Check arguments.
            if (xmlDoc == null)
                throw new ArgumentException(nameof(xmlDoc));
            if (rsaKey == null)
                throw new ArgumentException(nameof(rsaKey));

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml(xmlDoc);

            // Add the key to the SignedXml document.
            signedXml.SigningKey = rsaKey;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
        }

        // Verify the signature of an XML file against an asymmetric
        // algorithm and return the result.
        //https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-verify-the-digital-signatures-of-xml-documents
        public static Boolean VerifyXml(XmlDocument xmlDoc, RSA key)
        {
            // Check arguments.
            if (xmlDoc == null)
                throw new ArgumentException("xmlDoc");
            if (key == null)
                throw new ArgumentException("key");

            // Create a new SignedXml object and pass it
            // the XML document class.
            SignedXml signedXml = new SignedXml(xmlDoc);

            // Find the "Signature" node and create a new
            // XmlNodeList object.
            XmlNodeList nodeList = xmlDoc.GetElementsByTagName("Signature");

            // Throw an exception if no signature was found.
            if (nodeList.Count <= 0)
            {
                throw new CryptographicException("Verification failed: No Signature was found in the document.");
            }

            // This example only supports one signature for
            // the entire XML document.  Throw an exception
            // if more than one signature was found.
            if (nodeList.Count >= 2)
            {
                throw new CryptographicException("Verification failed: More that one signature was found for the document.");
            }

            // Load the first <signature> node.
            signedXml.LoadXml((XmlElement)nodeList[0]);

            // Check the signature and return the result.
            return signedXml.CheckSignature(key);
        }

        // convert a byte stream to a more readable comma seperated format. Suitable for dumping raw bits to a file
        public static string ToByteString(byte[] input)
        {
            string output = "{ ";

            //foreach(byte x in input)
            {
                output = output + BitConverter.ToString(input, 0);// + " , ";
            }

            output = output.Replace("-", ",");
            output += "}";

            return output;
        }

        // get the update.xml file location
        private static string GetPathForFileToSign(string currentDirectory)
        {
            string inputLocation = currentDirectory + "\\update.xml";
            Console.Write("Press [Enter] to accept default is current directory: \'" + inputLocation + "\']: ");

            string fileLocation = Console.ReadLine();

            if (String.IsNullOrEmpty(fileLocation))
            {
                fileLocation = inputLocation;
            }
            Console.WriteLine("\nUsing file: " + inputLocation + "\n");

            return fileLocation;
        }

        public static void Main()
        {
            Console.WriteLine("Update Encrypter version: " + MajorVersion + "." + MinorVersion + "\n");
            Console.WriteLine("Enter location of properly formatted updated platform info XML.");

            // get current working directory
            string currentDirectory = Directory.GetCurrentDirectory();

            // the the location of the update.xml file to sign
            string XMLInputFileLocation = GetPathForFileToSign(currentDirectory); 

            // Create a new 4096 bit RSA signing key and save it in the container.
            RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(4096);
            try
            {
                if (File.Exists(currentDirectory + FullRSAKeyFilename))
                {
                    // read the key from the file
                    TextReader keyFileReader = new StreamReader(currentDirectory + FullRSAKeyFilename);
                    string fullXMLKey = keyFileReader.ReadToEnd();
                    keyFileReader.Close();

                    // build a rsaKey from the input data
                    rsaKey.FromXmlString(fullXMLKey);
                }
            } catch(Exception ex)
            {
                Console.WriteLine("Error loading saved RSA key: " + ex.Message);
            }


            try {
                // Create a new XML container
                XmlDocument xmlDoc = new XmlDocument();

                // Load Update XML file into the XmlDocument object.
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(XMLInputFileLocation);

                // Sign the XML document
                SignXml(xmlDoc, rsaKey);
                xmlDoc.Save(currentDirectory + SignedOutputFilename);
                Console.WriteLine("XML file signed.");


                // extract the public and private keys for saving
                var exportedKey = rsaKey.ExportParameters(true);
                string fullKey = rsaKey.ToXmlString(true);  // public and private parts
                string pubKey = rsaKey.ToXmlString(false);  // public only part

                // write the full public key for the client XTU app to use if we haven't
                TextWriter keyFileWriter = null;
                if (!File.Exists(currentDirectory + PublicRSAKeyFilename))
                {
                    keyFileWriter = new StreamWriter(currentDirectory + PublicRSAKeyFilename);
                    keyFileWriter.WriteLine(pubKey);
                    keyFileWriter.Close();
                }
                // write the full public and private key if we haven't already
                // we MUST use the same private key from now on - and it must not leave Intel
                if (!File.Exists(currentDirectory + FullRSAKeyFilename))
                {
                    keyFileWriter = new StreamWriter(currentDirectory + FullRSAKeyFilename);
                    keyFileWriter.WriteLine(fullKey);
                    keyFileWriter.Close();
                }

                // create the public part of the key (this is for the client)
                RSACryptoServiceProvider importKey = new RSACryptoServiceProvider();
                importKey.FromXmlString(pubKey);                

                // Load the saved sign file to test it
                XmlDocument xmlDocI = new XmlDocument();
                xmlDocI.PreserveWhitespace = true;
                xmlDocI.Load(currentDirectory + SignedOutputFilename);                

                // verify the saves signed file with the loaded public key
                bool result = VerifyXml(xmlDocI, importKey);                            
                if (result)
                {
                    Console.WriteLine("The XML signature on "+ SignedOutputFilename+" is valid.");
                }
                else
                {
                    Console.WriteLine("SIGNING FAILED: The XML signature on " + SignedOutputFilename + " is not valid.");
                }
                RSACryptoServiceProvider staticPubKey = new RSACryptoServiceProvider();
                staticPubKey.FromXmlString(staticPublicKey);
                result = VerifyXml(xmlDocI, staticPubKey);
                if (result)
                {
                    Console.WriteLine("The XML signature is valid against the internal public key.");
                }
                else
                {
                    Console.WriteLine("The XML signature is not valid against the internal public key.");
                }
            } catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
    }
}
