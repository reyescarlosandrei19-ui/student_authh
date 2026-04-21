const jwt = require('jsonwebtoken');

exports.authorize = (roles = []) => {
    return (req, res, next) => {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(403).json({ message: "No token provided" });

        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) return res.status(401).json({ message: "Unauthorized" });

            // Check if the user's role is in the allowed list
            if (roles.length && !roles.includes(decoded.role)) {
                return res.status(403).json({ message: "Access Denied: Admins Only" });
            }

            req.user = decoded;
            next();
        });
    };
};