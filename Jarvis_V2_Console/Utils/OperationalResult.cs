namespace Jarvis_V2_Console.Utils;

    public class OperationResult<T>
    {
        public bool IsSuccess { get; private set; }
        public T? Data { get; private set; }
        public string? ErrorMessage { get; private set; }

        private OperationResult(bool isSuccess, T? data = default, string? errorMessage = null)
        {
            IsSuccess = isSuccess;
            Data = data;
            ErrorMessage = errorMessage;
        }

        public static OperationResult<T> Success(T data) => 
            new OperationResult<T>(true, data);

        public static OperationResult<T> Failure(string errorMessage) => 
            new OperationResult<T>(false, errorMessage: errorMessage);
    }