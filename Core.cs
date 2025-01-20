using HarmonyLib;
using MelonLoader;
using UnityEngine;

[assembly: MelonInfo(typeof(InsideInside.Core), "InsideInside", "1.0.0", "Quentin", null)]
[assembly: MelonGame("Playdead", "INSIDE")]

namespace InsideInside
{
    [HarmonyPatch("CheatManager", "get_cheatsEnabled")]
    class Patch
    {
        public static bool Prefix(ref bool __result)
        {
            __result = true;

            // skips the original
            return false;
        }
    }

    [HarmonyPatch("CheatManager", "IsActive")]
    class Patch2
    {
        public static bool Prefix(ref bool __result)
        {
            __result = true;

            // skips the original
            return false;
        }
    }

#if !FirstTimeSetup
    // Code to exclude from FirstTimeSetup configuration
    // The reason is that otherwise the project won't compile because of missing type reference to GameController

    [HarmonyPatch("CheatManager", "GetController")]
    class Patch3
    {
        public static bool Prefix(ref GameController __result)
        {
            __result = GameManager.controller;

            // skips the original
            return false;
        }
    }
#endif

    public class Core : MelonMod
    {
        public static MelonLogger.Instance Logger { get; private set; }

        public override void OnInitializeMelon()
        {
            Logger = LoggerInstance;

            HarmonyInstance.PatchAll();

            Logger.Msg("Initialized.");
        }

        public override void OnUpdate()
        {
            if (Input.GetKeyUp(KeyCode.K))
            {
#if FirstTimeSetup
                // Run this for retrieving
                // the decrypted BackgroundData.asset and Fog.asset game assemblies.
                // (Assembly-CSharp-firstpass / Assembly-CSharp)
                // You'll need them for interacting with the game code.
                MemoryScanner.ScanAndDumpPEFilesFromProcessMemory("C:/Users/Quentin/Desktop/InsideAssemblyDump");
#endif
            }
        }
    }
}