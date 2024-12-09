const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');
const cors = require('cors');
const dotenv = require('dotenv');
const csvWriter = require('csv-writer').createObjectCsvWriter;


dotenv.config();


const app = express();
app.use(express.json());
app.use(cors());

const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: 'library.db',
});

const User = sequelize.define('User', {
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
});

const Book = sequelize.define('Book', {
  title: { type: DataTypes.STRING, allowNull: false },
  author: { type: DataTypes.STRING, allowNull: false },
});

const BorrowRequest = sequelize.define('BorrowRequest', {
  startDate: { type: DataTypes.DATE, allowNull: false },
  endDate: { type: DataTypes.DATE, allowNull: false },
  status: { type: DataTypes.STRING, defaultValue: 'pending' },
});

const BorrowHistory = sequelize.define('BorrowHistory', {
  startDate: { type: DataTypes.DATE, allowNull: false },
  endDate: { type: DataTypes.DATE, allowNull: false },
});


User.hasMany(BorrowRequest);
Book.hasMany(BorrowRequest);
User.hasMany(BorrowHistory);
Book.hasMany(BorrowHistory);
BorrowRequest.belongsTo(User);
BorrowRequest.belongsTo(Book);
BorrowHistory.belongsTo(User);
BorrowHistory.belongsTo(Book);


sequelize.sync();


const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(403).json({ message: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};


app.post('/api/users', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email and password are required' });

  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = await User.create({ email, password: hashedPassword });
    res.status(201).json({ message: 'User created', userId: user.id });
  } catch (err) {
    res.status(500).json({ message: 'Error creating user' });
  }
});

app.get('/api/borrow-requests', authenticateJWT, async (req, res) => {
  const borrowRequests = await BorrowRequest.findAll({
    include: [User, Book],
  });
  res.json(borrowRequests);
});

app.put('/api/borrow-requests/:id/approve', authenticateJWT, async (req, res) => {
  const { id } = req.params;
  const borrowRequest = await BorrowRequest.findByPk(id);
  if (!borrowRequest) return res.status(404).json({ message: 'Borrow request not found' });

  // Check for overlapping dates
  const overlap = await BorrowRequest.findOne({
    where: {
      bookId: borrowRequest.bookId,
      status: 'approved',
      [Sequelize.Op.or]: [
        { startDate: { [Sequelize.Op.between]: [borrowRequest.startDate, borrowRequest.endDate] } },
        { endDate: { [Sequelize.Op.between]: [borrowRequest.startDate, borrowRequest.endDate] } },
      ],
    },
  });

  if (overlap) return res.status(400).json({ message: 'Book is already borrowed during the requested period' });

  borrowRequest.status = 'approved';
  await borrowRequest.save();
  res.json({ message: 'Borrow request approved' });
});

app.put('/api/borrow-requests/:id/deny', authenticateJWT, async (req, res) => {
  const { id } = req.params;
  const borrowRequest = await BorrowRequest.findByPk(id);
  if (!borrowRequest) return res.status(404).json({ message: 'Borrow request not found' });

  borrowRequest.status = 'denied';
  await borrowRequest.save();
  res.json({ message: 'Borrow request denied' });
});

app.get('/api/users/:id/history', authenticateJWT, async (req, res) => {
  const { id } = req.params;
  const borrowHistory = await BorrowHistory.findAll({
    where: { userId: id },
    include: [Book],
  });
  res.json(borrowHistory);
});


app.get('/api/books', async (req, res) => {
  const books = await Book.findAll();
  res.json(books);
});

app.post('/api/borrow-requests', authenticateJWT, async (req, res) => {
  const { userId, bookId, startDate, endDate } = req.body;
  if (!userId || !bookId || !startDate || !endDate)
    return res.status(400).json({ message: 'User ID, book ID, start date, and end date are required' });

  const overlap = await BorrowRequest.findOne({
    where: {
      bookId,
      status: 'approved',
      [Sequelize.Op.or]: [
        { startDate: { [Sequelize.Op.between]: [startDate, endDate] } },
        { endDate: { [Sequelize.Op.between]: [startDate, endDate] } },
      ],
    },
  });

  if (overlap) return res.status(400).json({ message: 'Book is already borrowed during the requested period' });

  const borrowRequest = await BorrowRequest.create({ userId, bookId, startDate, endDate, status: 'pending' });
  res.status(201).json(borrowRequest);
});

app.get('/api/users/:id/borrow-history/csv', authenticateJWT, async (req, res) => {
  const { id } = req.params;
  const borrowHistory = await BorrowHistory.findAll({ where: { userId: id }, include: [Book] });

  const csvFilePath = `borrow-history-${id}.csv`;
  const csvWriterInstance = csvWriter({
    path: csvFilePath,
    header: [
      { id: 'bookTitle', title: 'Book Title' },
      { id: 'startDate', title: 'Start Date' },
      { id: 'endDate', title: 'End Date' },
    ],
  });

  const records = borrowHistory.map((history) => ({
    bookTitle: history.Book.title,
    startDate: history.startDate,
    endDate: history.endDate,
  }));

  csvWriterInstance.writeRecords(records).then(() => {
    res.download(csvFilePath);
  });
});


app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(400).json({ message: 'User not found' });

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).json({ message: 'Invalid password' });

  const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: '1h',
  });
  res.json({ token });
});


app.listen(3000, () => {
  console.log('Server started on port 3000...');
});

