#pragma once

struct IntegrityStatus;

class Game {
public:
    // Call after payload decryption and monitor startup. Owns the game lifetime.
    static int Run(bool selfTest, const IntegrityStatus& integrity);

private:
    static void ImportantGameLogic();
    static int CalculateDamage(int base, int armor);
    static void RunSelfTest(const IntegrityStatus& integrity);
};
