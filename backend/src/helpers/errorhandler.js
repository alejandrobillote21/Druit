const errorHandler = ( err, req, res , next) => {
    // Check if response headers have already been sent to the client
    if (res.headersSent) {
        // If true, pass the error to the next error-handling Middleware
        return next(err);
    }

    // Set the status code of the response
    const statusCode = res.statusCode && res.statusCode >= 400 ? res.statusCode : 500;
    res.status(statusCode); // Set the status code of the response

    // Log error stack trace to the console if not in production --> For Debugging
    if (process.env.NODE_ENV !== "production") {
        console.log(err);
    }

    res.json({
        message: err.message,
        stack: process.env.NODE_ENV === "production" ? null : err.stack,
    });
};

export default errorHandler;