#ifndef ABE_LSSS_BENCH_POLICY_GENERATORS_H
#define ABE_LSSS_BENCH_POLICY_GENERATORS_H

#include <cmath>
#include <string>

inline std::string createAttribute(int attribute) {
    return "Attr_" + std::to_string(attribute);
}

inline std::string getBalancedOpenABETree(int start, int end) {
    if (start == end) {
        return createAttribute(start);
    }

    const int mid = static_cast<int>(std::ceil(start + (end - start) / 2.0));
    if (mid == 0) {
        return "(" + createAttribute(start) + " and " + createAttribute(end) + ")";
    }
    return "(" + getBalancedOpenABETree(start, mid - 1) + " and " +
        getBalancedOpenABETree(mid, end) + ")";
}

#endif
