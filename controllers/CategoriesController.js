import db from '../models/index.js';
import { CategoryNotFoundError } from "../errors/404/CategoryNotFound.js";
import { notifyUser } from '../websocket/notifyClients.js';
const Category = db.Category;

export async function getAll(req, res) {
    const categories = await Category.findAll();
    res.json(categories);
}

export async function getById(req, res) {
    const id = req.params.id;
    const category = await Category.findByPk(id);
    if (!category)
        throw new CategoryNotFoundError(id);

    res.json(category);
}

export async function create(req, res) {
    const { name } = req.body;
    const newCategory = await Category.create({ name });

    notifyUser(req.user.id, {
        event: "Category was created!",
        data: newCategory
    });

    res.status(201).json(newCategory);
}

export async function update(req, res) {
    const id = req.params.id;
    const { name } = req.body;
    const category = await Category.findByPk(id);
    if (!category) throw new CategoryNotFoundError(id);

    category.name = name ?? category.name;
    await category.save();

    notifyUser(req.user.id, {
        event: "Category was updated!",
        data: category
    });
    res.json(category);
}

export async function remove(req, res) {
    const id = req.params.id;
    const category = await Category.findByPk(id);
    if (!category) throw new CategoryNotFoundError(id);

    await category.destroy();

    notifyUser(req.user.id, {
        event: "Category was deleted!",
        data: newTodo
    });

    res.status(204);
}