using System;
using System.IO.IsolatedStorage;
using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

namespace WPCordovaClassLib.Cordova.Commands
{
  public sealed class SecureSettingsPlugin : BaseCommand
  {
    private static RNGCryptoServiceProvider randomNumberProvider = new RNGCryptoServiceProvider();

    public void get(string args)
    {
      string callbackId = "";

      try
      {
        JArray parameters = JArray.Parse(args);
        string name = (string) parameters[0];
        string value = null;

        IsolatedStorageSettings.ApplicationSettings.TryGetValue(name, out value);

        DispatchCommandResult(new PluginResult(PluginResult.Status.OK, value), callbackId);
      }
      catch (Exception e)
      {
        DispatchCommandResult(new PluginResult(PluginResult.Status.ERROR, e.Message), callbackId);
      }
    }

    public void set(string args)
    {
      string callbackId = "";

      try
      {
        JArray parameters = JArray.Parse(args);
        string name = (string) parameters[0];
        string value = (string) parameters[1];

        if (value == null)
        {
          IsolatedStorageSettings.ApplicationSettings.Remove(name);
        }
        else
        {
          IsolatedStorageSettings.ApplicationSettings[name] = value;
        }

        IsolatedStorageSettings.ApplicationSettings.Save();

        DispatchCommandResult(new PluginResult(PluginResult.Status.OK, value), callbackId);
      }
      catch (Exception e)
      {
        DispatchCommandResult(new PluginResult(PluginResult.Status.ERROR, e.Message), callbackId);
      }
    }

    public void createCryptographicKey(string args)
    {
      string callbackId = "";

      try
      {
        JArray parameters = JArray.Parse(args);
        int numBits = (int) parameters[0];

        if (numBits % 8 != 0)
        {
          throw new ApplicationException("number of bits must be divisble by 8");
        }

        byte[] buffer = new byte[numBits / 8];

        randomNumberProvider.GetBytes(buffer);

        string key = BitConverter.ToString(buffer).Replace("-", string.Empty);

        DispatchCommandResult(new PluginResult(PluginResult.Status.OK, key), callbackId);
      }
      catch (Exception e)
      {
        DispatchCommandResult(new PluginResult(PluginResult.Status.ERROR, e.Message), callbackId);
      }
    }

  }
}