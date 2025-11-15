import db from '../models/index.js';
import { Op } from 'sequelize';
import { ToDoNotFoundError } from "../errors/404/ToDoNotFoundError.js";
const Todo = db.Todo;
const Category = db.Category;
const User = db.User;

export async function getAll(req, res) {
    const { page, limit, offset } = getPaginationParams(req.query);
    const categoryId = req.query.category;
    const search = req.query.search;
    const sort = req.query.sort;

    const order = getSortOrder(sort);
    const where = getWhereClause(categoryId, search);

    if (req.user.role !== 'admin') {
        where.user_id = req.user.id;
    }

    const { count, rows } = await Todo.findAndCountAll({
        include: [
            {
                model: Category,
                as: 'category',
                attributes: ['name']
            }, {
                model: User,
                as: 'user',
                attributes: ['username']
            }
        ],
        where,
        order,
        limit,
        offset
    });

    const meta = getMeta(count, rows.length, limit, page);
    res.json({ data: rows, meta });
}

export async function getById(req, res) {
    const id = req.params.id;
    const todo = await Todo.findByPk(id);
    if (!todo) throw new ToDoNotFoundError(id);

    res.json(todo);
}

export async function create(req, res) {
    const { title, category_id } = req.body;
    const newTodo = await Todo.create({ title, category_id, user_id: req.user.id });
    res.status(201).json(newTodo);
}

export async function update(req, res) {
    const id = req.params.id;
    const { title, completed, category_id } = req.body;
    const todo = await Todo.findByPk(id);
    if (!todo) throw new ToDoNotFoundError(id);

    todo.title = title ?? todo.title;
    todo.category_id = category_id ?? todo.category_id;
    todo.completed = completed ?? todo.completed;

    await todo.save();
    res.json(todo);
}

export async function toggleCompleted(req, res) {
    const id = req.params.id;
    const todo = await Todo.findByPk(id);

    if (!todo) throw new ToDoNotFoundError(id);

    todo.completed = !todo.completed;
    await todo.save();
    res.json(todo);
}

export async function remove(req, res) {
    const id = req.params.id;
    const todo = await Todo.findByPk(id);
    if (!todo) throw new ToDoNotFoundError(id);

    await todo.destroy();
    res.status(204).send();
}

function getPaginationParams(query) {
    const page = parseInt(query.page) || 1;
    const limit = parseInt(query.limit) || 10;
    const offset = (page * limit) - limit;
    return { page, limit, offset };
}

function getSortOrder(sort) {
    if (!sort) return [['created_at', 'DESC']];

    const [field, direction] = sort.split(':');
    const validDirection = direction?.toUpperCase() === 'DESC' ? 'DESC' : 'ASC';
    let column;

    switch (field) {
        case 'createdAt': column = 'created_at'; break;
        case 'updatedAt': column = 'updated_at'; break;
        case 'dueDate': column = 'due_date'; break;
        default: column = 'created_at';
    }

    return [[column, validDirection]];
}

function getWhereClause(categoryId, search) {
    const where = {};
    if (categoryId) where.category_id = categoryId;
    if (search) where.title = { [Op.iLike]: `%${search}%` };
    return where;
}

function getMeta(count, rowsLength, limit, page) {
    return {
        total: count,
        count: rowsLength,
        limit,
        pages: Math.ceil(count / limit),
        currentPage: page,
    };
}





