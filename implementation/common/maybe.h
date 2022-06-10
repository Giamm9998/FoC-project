
template <class T> class Maybe {
  public:
    T result;
    char const *error;
    bool is_error;

    Maybe<T>() {
        result = T();
        is_error = false;
    }

    void set_error(char const *err) {
        error = err;
        is_error = true;
    }
    void set_result(T res) { result = res; }
};
