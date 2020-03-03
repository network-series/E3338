using System;
using System.IO.Ports;
using System.Threading;


namespace ConsoleApp1
{
    public class PortChat
    {
        static bool _continue;
        static SerialPort _serialPort;

        public static void Main()
        {
            string name;
            string message;
            StringComparer stringComparer = StringComparer.OrdinalIgnoreCase;
            Thread readThread = new Thread(Read);

            // 使用默认设置创建新的SerialPort对象。
            _serialPort = new SerialPort();
            // 允许用户设置适当的属性。
            _serialPort.PortName = SetPortName(_serialPort.PortName);
            _serialPort.BaudRate = SetPortBaudRate(_serialPort.BaudRate);
            _serialPort.Parity = SetPortParity(_serialPort.Parity);
            _serialPort.DataBits = SetPortDataBits(_serialPort.DataBits);
            _serialPort.StopBits = SetPortStopBits(_serialPort.StopBits);
            _serialPort.Handshake = SetPortHandshake(_serialPort.Handshake);
            // 设置读/写超时
            _serialPort.ReadTimeout = 500;
            _serialPort.WriteTimeout = 500;
            _serialPort.Open();
            _continue = true;
            readThread.Start();
            Console.Write("Name: ");
            name = Console.ReadLine();
            Console.WriteLine("键入QUIT退出");
            while (_continue)
            {
                message = Console.ReadLine();
                // 允许用户设置适当的属性。 
                if (stringComparer.Equals("quit", message))
                {
                    _continue = false;
                }
                else
                {
                    //时间
                    System.DateTime currentTime = new System.DateTime();
                    currentTime = System.DateTime.Now;
                    string strTime = currentTime.ToString();
                    //信息
                    message = "[SENT " + strTime + "]" + message;
                    Console.WriteLine(message);
                    _serialPort.WriteLine(String.Format("<{0}>: {1}", name, message));
                }
            }
            readThread.Join();
            _serialPort.Close();
        }
      
    public static void Read()
        {
            while (_continue)
            {
                try
                {
                    string message = _serialPort.ReadLine();
                    Console.WriteLine(message);
                }
                catch (TimeoutException)
                { }
            }
        }

        //显示端口值并提示用户输入端口。 
        public static string SetPortName(string defaultPortName)
        {
            string portName;
            Console.WriteLine("可用端口：");
            foreach (string s in SerialPort.GetPortNames())
            {
                Console.WriteLine("   {0}", s);
            }
            Console.Write("输入COM端口值（默认值：{0}）： ", defaultPortName);
            portName = Console.ReadLine();
            if (portName == "" || !(portName.ToLower()).StartsWith("com"))
            {
                portName = defaultPortName;
            }
            return portName;
        }

        // 显示波特率值并提示用户输入值。 
        public static int SetPortBaudRate(int defaultPortBaudRate)
        {
            string baudRate; Console.Write("波特率（默认值：{0}）： ", defaultPortBaudRate);
            baudRate = Console.ReadLine();
            if (baudRate == "")
            {
                baudRate = defaultPortBaudRate.ToString();
            }
            return int.Parse(baudRate);
        }

        // 显示端口奇偶校验值并提示用户输入值。 
        public static Parity SetPortParity(Parity defaultPortParity)
        {
            string parity;
            Console.WriteLine("可用奇偶校验选项：");
            foreach (string s in Enum.GetNames(typeof(Parity)))
            {
                Console.WriteLine("   {0}", s);
            }
            Console.Write("输入奇偶校验值（默认值：{0}）：", defaultPortParity.ToString(), true);
            parity = Console.ReadLine(); if (parity == "")
            {
                parity = defaultPortParity.ToString();
            }
            return (Parity)Enum.Parse(typeof(Parity), parity, true);
        }

        // 显示数据位值并提示用户输入值。
        public static int SetPortDataBits(int defaultPortDataBits)
        {
            string dataBits;
            Console.Write("输入数据位值（默认值：{0}）： ", defaultPortDataBits);
            dataBits = Console.ReadLine();
            if (dataBits == "")
            {
                dataBits = defaultPortDataBits.ToString();
            }
            return int.Parse(dataBits.ToUpperInvariant());
        }

        // 显示StopBits值并提示用户输入值。
        public static StopBits SetPortStopBits(StopBits defaultPortStopBits)
        {
            string stopBits; Console.WriteLine("可用的停止位选项：");
            foreach (string s in Enum.GetNames(typeof(StopBits)))
            {
                Console.WriteLine("   {0}", s);
            }
            Console.Write("输入StopBits值（不支持None，并且 \n" + "引发参数超出范围异常。 \n （默认值：{0}）：", defaultPortStopBits.ToString());
            stopBits = Console.ReadLine();
            if (stopBits == "")
            {
                stopBits = defaultPortStopBits.ToString();
            }
            return (StopBits)Enum.Parse(typeof(StopBits), stopBits, true);
        }

        public static Handshake SetPortHandshake(Handshake defaultPortHandshake)
        {
            string handshake;
            Console.WriteLine("可用Handshake选项：");
            foreach (string s in Enum.GetNames(typeof(Handshake)))
            {
                Console.WriteLine("   {0}", s);
            }
            Console.Write("键入Handshake值(默认: {0}):", defaultPortHandshake.ToString());
            handshake = Console.ReadLine();
            if (handshake == "")
            {
                handshake = defaultPortHandshake.ToString();
            }
            return (Handshake)Enum.Parse(typeof(Handshake), handshake, true);
        }
    }
}

    
