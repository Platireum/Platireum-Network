#ifndef BLOCKCHAIN_SERIALIZER_H
#define BLOCKCHAIN_SERIALIZER_H

#include <string>
#include <memory> // For std::shared_ptr

/**
 * @brief Namespace for serialization utilities.
 * This can be used to group all serialization-related functions.
 */
namespace Serializer {

    /**
     * @brief Interface for objects that can be serialized to a string.
     * Any class wishing to be serializable should inherit from this.
     * This ensures a common 'serialize' method.
     */
    class ISerializable {
    public:
        virtual ~ISerializable() = default;

        /**
         * @brief Serializes the object into a string representation.
         * @return A string representing the serialized object.
         */
        virtual std::string serialize() const = 0; // Pure virtual function
    };

    /**
     * @brief Helper function to deserialize a string into an object of type T.
     * This is a template function that expects the type T to have a static
     * deserialize(const std::string&) method.
     *
     * @tparam T The type of object to deserialize (e.g., Transaction, Block).
     * @param data The string data to deserialize.
     * @return A shared_ptr to the deserialized object.
     * @throws std::runtime_error if deserialization fails.
     */
    template <typename T>
    std::shared_ptr<T> deserialize(const std::string& data) {
        // This assumes that the class T has a static deserialize method
        // that returns a shared_ptr<T> and takes a const std::string&.
        // For example: static std::shared_ptr<Transaction> Transaction::deserialize(const std::string&);
        return T::deserialize(data);
    }

    // You could also add specific serialization functions if needed,
    // for types that don't directly implement ISerializable or for
    // more complex nested structures.

    // Example: For serializing basic types if not directly handled
    // std::string serializeString(const std::string& s);
    // std::string deserializeString(const std::string& s);

    // std::string serializeInt(int i);
    // int deserializeInt(const std::string& s);

    // ... and so on for other data types if a generic approach is insufficient.

} // namespace Serializer

#endif // BLOCKCHAIN_SERIALIZER_H