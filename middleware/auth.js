const jwt = require('jsonwebtoken');
const { JWT_SECRET } = process.env;  // Asegúrate de tener una clave secreta

const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(403).json({ message: 'Acceso denegado. No se proporcionó token.' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token no válido' });
        }
        
        req.user = decoded;  // Decodifica el token y agrega los datos del usuario a la solicitud
        next();  // Pasa al siguiente middleware o ruta
    });
};

module.exports = authenticateToken;