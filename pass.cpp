// Генератор паролей, C++17. Исходник сохранён в UTF-8.
// Windows (Developer Command Prompt):
//   cl /std:c++17 /EHsc /utf-8 password_generator.cpp bcrypt.lib
// Linux: g++ -std=c++17 -O2 -Wall -Wextra -pedantic password_generator.cpp -o passwords
// macOS: clang++ -std=c++17 -O2 -Wall -Wextra password_generator.cpp -o passwords
// Запуск: passwords.exe (Windows) или ./passwords (Linux/macOS).
#include <cstdint>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <unordered_set>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif
#elif defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <stdlib.h>
#else
#error Unsupported OS: implement a system CSPRNG before using this program.
#endif

// 1. Получаем случайные биты непосредственно из криптографического ГСЧ ОС.
// rand(), время и mt19937 не подходят: их состояние можно предсказывать.
// При отказе ОС прекращаем работу, не переключаемся на слабый генератор.
std::uint32_t random32() {
    std::uint32_t value = 0;
#ifdef _WIN32
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&value), sizeof(value),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw std::runtime_error("BCryptGenRandom failed");
#elif defined(__linux__)
    auto* p = reinterpret_cast<unsigned char*>(&value);
    std::size_t done = 0;
    while (done < sizeof(value)) {
        const auto n = getrandom(p + done, sizeof(value) - done, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) throw std::runtime_error("getrandom failed");
        done += static_cast<std::size_t>(n);
    }
#elif defined(__APPLE__)
    arc4random_buf(&value, sizeof(value));
#endif
    return value;
}

// 2. Равномерное число [0, bound). Простое x % bound в общем случае
// даёт смещение. Отбрасываем неполный остаток диапазона 2^32.
std::uint32_t uniform(std::uint32_t bound) {
    if (bound == 0) throw std::invalid_argument("Empty alphabet");
    const std::uint64_t range = std::uint64_t{ 1 } << 32;
    const auto limit = range - range % bound;
    std::uint32_t x;
    do { x = random32(); } while (x >= limit);
    return x % bound;
}

// 3. 64 разных ASCII-символа: один независимый выбор даёт ровно 6 бит.
// Не требуем обязательного присутствия каждой категории: это изменило бы
// распределение и потребовало бы другой формулы энтропии.
const std::string alphabet =
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@";

// 4. Самодостаточный учебный словарь из 64 уникальных английских слов.
// Каждое слово даёт 6 бит, поэтому стойкая фраза получается длинной.
// Для более коротких фраз можно заменить словарь на проверенные 7776 слов:
// тогда каждое слово даст log2(7776) ≈ 12.925 бит. Размер учитывается автоматически.
// Повторы слов разрешены: выборы независимы, запрещать повторы не нужно.
const std::vector<std::string> words = {
    "apple", "river", "cloud", "stone", "tiger", "forest", "ocean", "copper",
    "maple", "eagle", "lemon", "piano", "train", "bridge", "planet", "silver",
    "bread", "chair", "dream", "flame", "glass", "horse", "island", "jacket",
    "kite", "lamp", "moon", "needle", "olive", "paper", "queen", "rocket",
    "sand", "table", "umbrella", "violet", "window", "yellow", "zebra", "anchor",
    "basket", "castle", "desert", "engine", "feather", "garden", "harbor", "insect",
    "jungle", "kernel", "ladder", "magnet", "napkin", "orange", "pencil", "rabbit",
    "saddle", "temple", "velvet", "walnut", "yogurt", "zipper", "button", "candle"
};

struct Profile { int characters; int phraseWords; int mixedWords; int mixedChars; };
const Profile profiles[] = { {16, 16, 8, 8}, {20, 20, 12, 8}, {24, 24, 16, 8} };

// 5. Читаем всю строку: отклоняем мусор, дроби и выход за диапазон.
// EOF корректно завершает программу, включая ввод из файла/конвейера.
int ask(const std::string& prompt, int low, int high) {
    for (;;) {
        std::cout << prompt << std::flush;
        std::string line;
        if (!std::getline(std::cin, line)) return -1;
        std::istringstream in(line);
        int value;
        char extra;
        if ((in >> value) && !(in >> extra) && value >= low && value <= high)
            return value;
        std::cout << "Введите целое число от " << low << " до " << high << ".\n";
    }
}

std::string randomString(int length) {
    std::string result;
    for (int i = 0; i < length; ++i)
        result += alphabet[uniform(static_cast<std::uint32_t>(alphabet.size()))];
    return result;
}
std::string randomPhrase(int count) {
    std::string result;
    for (int i = 0; i < count; ++i) {
        if (i) result += '-';
        result += words[uniform(static_cast<std::uint32_t>(words.size()))];
    }
    return result;
}

// 6. Проверяем предпосылки формулы: уникальность и однозначное разделение.
// В комбинированном режиме точка отделяет фразу от случайного суффикса.
void validate() {
    std::unordered_set<std::string> unique(words.begin(), words.end());
    std::unordered_set<char> symbols(alphabet.begin(), alphabet.end());
    if (unique.size() != words.size() || words.size() < 2 ||
        symbols.size() != alphabet.size() || alphabet.size() < 2)
        throw std::runtime_error("Invalid dictionary/alphabet");
    for (const auto& word : words)
        if (word.empty() || word.find_first_not_of("abcdefghijklmnopqrstuvwxyz") != std::string::npos)
            throw std::runtime_error("Words must contain only a-z");
}

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    try {
        validate();
        std::cout << "Генератор паролей: случайность от ОС, без сохранения в файл.\n"
            << "Лёгкий означает более короткий, минимальная энтропия — 96 бит.\n";
        for (;;) {
            int level = ask("\nСложность: 1 — лёгкий, 2 — средний, 3 — сложный, 0 — выход: ", 0, 3);
            if (level <= 0) break;
            int type = ask("Тип: 1 — строка, 2 — парольная фраза, 3 — комбинированный: ", 1, 3);
            if (type < 0) break;
            int count = ask("Сколько паролей (1–100): ", 1, 100);
            if (count < 0) break;
            const auto& p = profiles[level - 1];
            for (int i = 0; i < count; ++i) {
                std::string password;
                int nc = 0, nw = 0;
                if (type == 1) { nc = p.characters; password = randomString(nc); }
                else if (type == 2) { nw = p.phraseWords; password = randomPhrase(nw); }
                else {
                    nc = p.mixedChars; nw = p.mixedWords;
                    password = randomPhrase(nw) + '.' + randomString(nc);
                }
                // 7. Энтропия распределения генератора, а не оценка внешнего вида:
                // H = L*log2(A) + W*log2(D). Фиксированные разделители дают 0 бит.
                // При равномерных независимых выборах Shannon H = min-entropy.
                const double h = nc * std::log2(alphabet.size()) + nw * std::log2(words.size());
                // Для N равновероятных вариантов среднее число попыток (N+1)/2.
                // 1e12 — условная скорость, не измерение ИИ или конкретного хеша.
                const double years = (std::exp2(h) + 1) / 2 / 1e12 / (365.25 * 86400);
                std::cout << "\nПароль " << i + 1 << ": " << password
                    << "\nСимволов: " << password.size() << "; слов: " << nw
                    << "; случайных символов: " << nc
                    << "\nH = " << nc << "*log2(" << alphabet.size() << ") + "
                    << nw << "*log2(" << words.size() << ") = " << std::fixed
                    << std::setprecision(2) << h << " бит."
                    << "\nСредний перебор при условных 10^12 попыток/с: "
                    << std::scientific << std::setprecision(2) << years << " лет.\n"
                    << std::defaultfloat;
                std::cout << "Обоснование: независимые равномерные выборы дают 2^H вариантов.\n"
                    << "ИИ, знающий алгоритм и словарь, не получает преимущества от\n"
                    << "человеческих шаблонов: здесь нет цитат, грамматики и личных данных.\n"
                    << "Стойкость предполагает исправный CSPRNG и отсутствие утечки.\n";
                if (type != 1)
                    std::cout << "Слова выбраны независимо; смысловая фраза не используется.\n"
                    << "Маленький словарь требует большего числа слов для той же энтропии.\n";
            }
        }
        // Не пишем пароли в файлы и не отправляем по сети. Однако терминал
        // сохраняет историю вывода; std::string не гарантирует стирание памяти.
        // Не обрезайте и не редактируйте результат: расчёт H тогда неприменим.
        // Реальная защита зависит также от хеша сервиса, лимита попыток и MFA.
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << ". Генерация остановлена.\n";
        return 1;
    }
}
