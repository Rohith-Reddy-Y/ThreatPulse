const a = async () => ({ data: {} }); a.get = a; a.post = a; a.create = () => a; module.exports = a;
