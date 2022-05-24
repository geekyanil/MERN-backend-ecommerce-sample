module.exports = (theErrorFunc) => (req, res, next) => {
  Promise.resolve(theErrorFunc(req, res, next)).catch(next);
};
