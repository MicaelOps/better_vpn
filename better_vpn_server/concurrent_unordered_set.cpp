//
// Created by Micael Cossa on 19/07/2025.
//

#include "concurrent_unordered_set.h"

template<typename Type>
void concurrent_unordered_set<Type>::remove(Type data) {

    std::lock_guard<std::mutex> lock(setMutex);
    original_set.erase(data);
}

template<typename Type>
void concurrent_unordered_set<Type>::insert(Type data) {
    std::lock_guard<std::mutex> lock(setMutex);
    original_set.emplace(data);
}

template<typename Type>
void concurrent_unordered_set<Type>::clear() {
    std::lock_guard<std::mutex> lock(setMutex);
    original_set.clear();
}

template class concurrent_unordered_set<unsigned long long>;