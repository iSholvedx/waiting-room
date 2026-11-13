
import { sql } from '../lib/db.js';

import {
  hash,
  parseCookies,
  verifyPassToken
} from '../lib/security.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store, max-age=0');
  res.setHeader('Vary', 'Cookie');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.setHeader('Allow', 'GET, HEAD');
    res.statusCode = 405;
    return res.end('Method not allowed');
  }

  try {
    // =========================================
    // 1. AUTHENTICATION
    // =========================================

    const cookies = parseCookies(req);
    const queueToken = cookies.wr_queue;
    const passToken = cookies.wr_passed;

    if (!queueToken || !passToken) {
      res.statusCode = 403;
      return res.end('Admission required');
    }

    const [session] = await sql`
      SELECT *
      FROM queue_sessions
      WHERE token_hash = ${hash(queueToken)}
      LIMIT 1
    `;

    const now = Date.now();

    if (
      !session ||
      !['admitted', 'entered'].includes(session.status) ||
      !session.expires_at ||
      Number(session.expires_at) <= now ||
      !verifyPassToken(passToken, session)
    ) {
      res.statusCode = 403;
      return res.end('Admission required');
    }

    // Ubah status menjadi entered.
    if (session.status === 'admitted') {
      const updated = await sql`
        UPDATE queue_sessions
        SET status = 'entered'
        WHERE id = ${session.id}
          AND status = 'admitted'
          AND expires_at > ${now}
        RETURNING id
      `;

      if (updated.length !== 1) {
        res.statusCode = 403;
        return res.end('Admission expired');
      }
    }

    // =========================================
    // 2. PROTECTED FOOD ORDERING PAGE
    // =========================================

    const html = `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="theme-color" content="#10131c">

  <title>Crave - Food & Drinks</title>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">

  <style>
    :root {
      --bg: #10131c;
      --surface: #191e2a;
      --surface-2: #222938;
      --border: rgba(255,255,255,.08);
      --text: #f5f6fa;
      --muted: #929bad;
      --orange: #ff914d;
      --orange-dark: #e97835;
      --green: #4bd6a0;
      --radius: 18px;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'DM Sans', sans-serif;
      min-height: 100vh;
    }

    button, input {
      font: inherit;
    }

    button {
      cursor: pointer;
    }

    .navbar {
      height: 76px;
      padding: 0 7%;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--border);
      background: rgba(16,19,28,.94);
      position: sticky;
      top: 0;
      z-index: 20;
      backdrop-filter: blur(16px);
    }

    .brand {
      font-family: 'Outfit', sans-serif;
      font-size: 25px;
      font-weight: 800;
      letter-spacing: -1px;
    }

    .brand span {
      color: var(--orange);
    }

    .nav-right {
      display: flex;
      align-items: center;
      gap: 20px;
    }

    .status {
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--green);
      font-size: 12px;
      font-weight: 700;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 12px var(--green);
    }

    .cart-button {
      border: 0;
      background: var(--orange);
      color: #171717;
      border-radius: 12px;
      padding: 11px 17px;
      font-weight: 800;
      display: flex;
      align-items: center;
      gap: 9px;
    }

    .cart-count {
      background: #171717;
      color: white;
      min-width: 21px;
      height: 21px;
      display: grid;
      place-items: center;
      border-radius: 50%;
      font-size: 11px;
    }

    .container {
      max-width: 1200px;
      width: 86%;
      margin: auto;
    }

    .hero {
      margin-top: 38px;
      min-height: 270px;
      border-radius: 26px;
      padding: 45px 50px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      overflow: hidden;
      background:
        radial-gradient(circle at 80% 40%, rgba(255,145,77,.22), transparent 30%),
        linear-gradient(120deg, #252b3b, #191e2a);
      border: 1px solid var(--border);
    }

    .hero-content {
      max-width: 560px;
      position: relative;
      z-index: 1;
    }

    .eyebrow {
      color: var(--orange);
      font-size: 12px;
      letter-spacing: 2px;
      font-weight: 800;
      text-transform: uppercase;
      margin-bottom: 15px;
    }

    .hero h1 {
      font-family: 'Outfit', sans-serif;
      font-size: clamp(32px, 5vw, 52px);
      line-height: 1.1;
      letter-spacing: -1.8px;
      margin-bottom: 14px;
    }

    .hero h1 span {
      color: var(--orange);
    }

    .hero p {
      color: var(--muted);
      line-height: 1.7;
      font-size: 14px;
      max-width: 420px;
    }

    .hero-emoji {
      font-size: 115px;
      filter: drop-shadow(0 15px 20px rgba(0,0,0,.3));
      transform: rotate(-9deg);
    }

    .section-heading {
      margin: 43px 0 22px;
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 15px;
    }

    .section-heading h2 {
      font-family: 'Outfit', sans-serif;
      font-size: 27px;
    }

    .section-heading p {
      color: var(--muted);
      font-size: 13px;
      margin-top: 5px;
    }

    .categories {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 26px;
    }

    .category-btn {
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--muted);
      padding: 12px 20px;
      border-radius: 12px;
      font-weight: 700;
      transition: .2s;
    }

    .category-btn:hover,
    .category-btn.active {
      background: rgba(255,145,77,.13);
      border-color: var(--orange);
      color: var(--orange);
    }

    .menu-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 20px;
    }

    .food-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
      transition: transform .2s, border-color .2s;
    }

    .food-card:hover {
      transform: translateY(-4px);
      border-color: rgba(255,145,77,.45);
    }

    .food-image {
      height: 180px;
      background: var(--surface-2);
      position: relative;
      overflow: hidden;
    }

    .food-image img {
      width: 100%;
      height: 100%;
      object-fit: cover;
      display: block;
      transition: transform .35s;
    }

    .food-card:hover .food-image img {
      transform: scale(1.05);
    }

    .food-info {
      padding: 18px;
    }

    .food-info h3 {
      font-family: 'Outfit', sans-serif;
      font-size: 18px;
      margin-bottom: 7px;
    }

    .food-info p {
      color: var(--muted);
      font-size: 12px;
      line-height: 1.6;
      min-height: 39px;
    }

    .food-bottom {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-top: 17px;
    }

    .price {
      color: var(--orange);
      font-size: 16px;
      font-weight: 800;
    }

    .add-button {
      border: 0;
      border-radius: 10px;
      background: var(--orange);
      color: #171717;
      padding: 10px 15px;
      font-weight: 800;
      font-size: 12px;
    }

    .add-button:hover,
    .cart-button:hover {
      background: #ffab73;
    }

    .cart-section {
      margin: 48px 0 60px;
      padding: 27px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 22px;
    }

    .cart-section h2 {
      font-family: 'Outfit', sans-serif;
      margin-bottom: 22px;
    }

    .empty-cart {
      text-align: center;
      padding: 30px 10px;
      color: var(--muted);
    }

    .empty-cart .emoji {
      font-size: 38px;
      margin-bottom: 12px;
    }

    .cart-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 15px 0;
      border-bottom: 1px solid var(--border);
    }

    .cart-item-name {
      font-weight: 700;
      font-size: 14px;
    }

    .cart-item-price {
      color: var(--muted);
      font-size: 12px;
      margin-top: 5px;
    }

    .quantity {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .quantity button {
      border: 1px solid var(--border);
      background: var(--surface-2);
      color: white;
      border-radius: 8px;
      width: 29px;
      height: 29px;
      font-weight: 800;
    }

    .cart-total {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-top: 22px;
      margin-top: 5px;
      font-size: 16px;
      font-weight: 800;
    }

    .cart-total strong {
      color: var(--orange);
      font-size: 21px;
    }

    .checkout-button {
      margin-top: 20px;
      width: 100%;
      border: 0;
      border-radius: 12px;
      background: var(--orange);
      color: #171717;
      padding: 15px;
      font-weight: 800;
      font-size: 14px;
    }

    .checkout-button:disabled {
      opacity: .4;
      cursor: not-allowed;
    }

    .checkout-form {
      display: none;
      margin-top: 22px;
      padding-top: 20px;
      border-top: 1px solid var(--border);
    }

    .checkout-form.show {
      display: block;
    }

    .checkout-form label {
      display: block;
      font-size: 12px;
      font-weight: 700;
      margin: 15px 0 8px;
    }

    .checkout-form input {
      width: 100%;
      padding: 13px;
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 10px;
      outline: none;
      color: white;
    }

    .checkout-form input:focus {
      border-color: var(--orange);
    }

    .checkout-form input::placeholder {
      color: #788195;
    }

    .submit-order {
      width: 100%;
      margin-top: 20px;
      padding: 14px;
      border: 0;
      border-radius: 10px;
      background: var(--green);
      color: #10251d;
      font-weight: 800;
    }

    .footer {
      border-top: 1px solid var(--border);
      padding: 25px;
      text-align: center;
      color: var(--muted);
      font-size: 12px;
    }

    .toast {
      position: fixed;
      bottom: 25px;
      left: 50%;
      transform: translate(-50%, 20px);
      background: #252d3b;
      border: 1px solid var(--border);
      padding: 13px 20px;
      border-radius: 12px;
      font-size: 13px;
      opacity: 0;
      pointer-events: none;
      transition: .25s;
      z-index: 50;
    }

    .toast.show {
      opacity: 1;
      transform: translate(-50%, 0);
    }

    @media (max-width: 850px) {
      .menu-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }

      .hero-emoji {
        font-size: 80px;
      }

      .container {
        width: 90%;
      }
    }

    @media (max-width: 560px) {
      .navbar {
        height: 65px;
        padding: 0 5%;
      }

      .brand {
        font-size: 22px;
      }

      .status {
        display: none;
      }

      .hero {
        margin-top: 22px;
        padding: 30px 23px;
        min-height: 230px;
      }

      .hero-emoji {
        font-size: 55px;
      }

      .hero h1 {
        font-size: 34px;
      }

      .hero p {
        font-size: 12px;
      }

      .menu-grid {
        grid-template-columns: 1fr;
        gap: 14px;
      }

      .food-image {
        height: 200px;
      }

      .section-heading h2 {
        font-size: 23px;
      }

      .cart-section {
        padding: 20px;
      }

      .categories {
        gap: 8px;
      }

      .category-btn {
        padding: 10px 14px;
        font-size: 12px;
      }
    }
  </style>
</head>

<body>

  <header class="navbar">
    <div class="brand">crave<span>.</span></div>

    <div class="nav-right">
      <div class="status">
        <span class="status-dot"></span>
        ACCESS GRANTED
      </div>

      <button class="cart-button" id="cartButton">
        🛒 Keranjang
        <span class="cart-count" id="cartCount">0</span>
      </button>
    </div>
  </header>

  <main class="container">

    <section class="hero">
      <div class="hero-content">
        <div class="eyebrow">GOOD FOOD, GOOD MOOD</div>

        <h1>
          Laper? <span>Let's Eat.</span>
        </h1>

        <p>
          Temukan makanan dan minuman favoritmu.
          Pilih menu, masukkan keranjang, dan checkout
          dengan mudah.
        </p>
      </div>

      <div class="hero-emoji">🍔</div>
    </section>

    <section>
      <div class="section-heading">
        <div>
          <h2>Explore Menu</h2>
          <p>Pilih makanan atau minuman favoritmu.</p>
        </div>
      </div>

      <div class="categories">
        <button class="category-btn active" data-category="all">
          ✨ Semua
        </button>

        <button class="category-btn" data-category="makanan">
          🍔 Makanan
        </button>

        <button class="category-btn" data-category="minuman">
          🥤 Minuman
        </button>
      </div>

      <div class="menu-grid" id="menuGrid"></div>
    </section>

    <section class="cart-section" id="cartSection">
      <h2>🛒 Keranjang Belanja</h2>

      <div id="cartItems">
        <div class="empty-cart">
          <div class="emoji">🛍️</div>
          <p>Keranjangmu masih kosong.</p>
          <p>Yuk, pilih menu favoritmu!</p>
        </div>
      </div>

      <div class="cart-total">
        <span>Total Pembayaran</span>
        <strong id="cartTotal">Rp0</strong>
      </div>

      <button
        class="checkout-button"
        id="checkoutButton"
        disabled
      >
        Lanjut Checkout →
      </button>

      <form class="checkout-form" id="checkoutForm">
        <h3>Detail Pemesanan</h3>

        <label for="customerName">Nama lengkap</label>
        <input
          id="customerName"
          type="text"
          maxlength="80"
          placeholder="Masukkan nama kamu"
          autocomplete="name"
          required
        >

        <label for="customerPhone">Nomor WhatsApp</label>
        <input
          id="customerPhone"
          type="tel"
          maxlength="20"
          placeholder="Contoh: 081234567890"
          autocomplete="tel"
          required
        >

        <button type="submit" class="submit-order">
          Buat Pesanan
        </button>
      </form>
    </section>

  </main>

  <footer class="footer">
    © 2026 Crave Food & Drinks. Made with ❤️
  </footer>

  <div class="toast" id="toast" role="status" aria-live="polite"></div>

  <script>
    // =========================================
    // MENU DATA
    // =========================================

    const products = [
      {
        id: 1,
        name: 'Classic Beef Burger',
        category: 'makanan',
        price: 28000,
        description: 'Beef patty, fresh lettuce, cheese dan special sauce.',
        image: 'https://images.unsplash.com/photo-1568901346375-23c9450c58cd?w=700&q=85'
      },
      {
        id: 2,
        name: 'Chicken Crispy',
        category: 'makanan',
        price: 22000,
        description: 'Ayam crispy dengan bumbu gurih dan renyah.',
        image: 'https://images.unsplash.com/photo-1626082927389-6cd097cdc6ec?w=700&q=85'
      },
      {
        id: 3,
        name: 'French Fries',
        category: 'makanan',
        price: 15000,
        description: 'Kentang goreng renyah dengan taburan garam.',
        image: 'https://images.unsplash.com/photo-1573080496219-bb080dd4f877?w=700&q=85'
      },
      {
        id: 4,
        name: 'Chicken Rice Bowl',
        category: 'makanan',
        price: 25000,
        description: 'Nasi hangat dengan ayam dan saus pilihan.',
        image: 'https://images.unsplash.com/photo-1512058564366-18510be2db19?w=700&q=85'
      },
      {
        id: 5,
        name: 'Iced Matcha Latte',
        category: 'minuman',
        price: 18000,
        description: 'Matcha premium dengan susu creamy dan es.',
        image: 'https://images.unsplash.com/photo-1515823064-d6e0c04616a7?w=700&q=85'
      },
      {
        id: 6,
        name: 'Iced Coffee',
        category: 'minuman',
        price: 16000,
        description: 'Kopi dingin dengan rasa yang seimbang.',
        image: 'https://images.unsplash.com/photo-1461023058943-07fcbe16d735?w=700&q=85'
      },
      {
        id: 7,
        name: 'Fresh Orange Juice',
        category: 'minuman',
        price: 14000,
        description: 'Jus jeruk segar, manis dan menyegarkan.',
        image: 'https://images.unsplash.com/photo-1600271886742-f049cd451bba?w=700&q=85'
      },
      {
        id: 8,
        name: 'Strawberry Milk',
        category: 'minuman',
        price: 19000,
        description: 'Susu segar dengan rasa strawberry.',
        image: 'https://images.unsplash.com/photo-1553787499-6f9133860278?w=700&q=85'
      }
    ];

    // =========================================
    // STATE
    // =========================================

    const cart = {};
    let activeCategory = 'all';

    const menuGrid = document.getElementById('menuGrid');
    const cartItems = document.getElementById('cartItems');
    const cartCount = document.getElementById('cartCount');
    const cartTotal = document.getElementById('cartTotal');
    const checkoutButton = document.getElementById('checkoutButton');
    const checkoutForm = document.getElementById('checkoutForm');
    const toast = document.getElementById('toast');

    const formatRupiah = (amount) => {
      return new Intl.NumberFormat('id-ID', {
        style: 'currency',
        currency: 'IDR',
        maximumFractionDigits: 0
      }).format(amount);
    };

    function escapeHTML(value) {
      return String(value).replace(/[&<>"']/g, function(char) {
        const entities = {
          '&': '&amp;',
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#39;'
        };

        return entities[char];
      });
    }

    function showToast(message) {
      toast.textContent = message;
      toast.classList.add('show');

      window.clearTimeout(showToast.timer);

      showToast.timer = window.setTimeout(function() {
        toast.classList.remove('show');
      }, 2200);
    }

    // =========================================
    // RENDER PRODUCTS
    // =========================================

    function renderProducts() {
  const filtered = products.filter(function(product) {
    return activeCategory === 'all' ||
      product.category === activeCategory;
  });

  menuGrid.innerHTML = filtered.map(function(product) {
    return '<article class="food-card">' +
      '<div class="food-image">' +
        '<img src="' + escapeHTML(product.image) + '" ' +
        'alt="' + escapeHTML(product.name) + '" ' +
        'loading="lazy" onerror="this.style.display=\'none\'">' +
      '</div>' +
      '<div class="food-info">' +
        '<h3>' + escapeHTML(product.name) + '</h3>' +
        '<p>' + escapeHTML(product.description) + '</p>' +
        '<div class="food-bottom">' +
          '<span class="price">' +
            formatRupiah(product.price) +
          '</span>' +
          '<button class="add-button" data-add="' +
            product.id + '">+ Tambah</button>' +
        '</div>' +
      '</div>' +
    '</article>';
  }).join('');
}

    // =========================================
    // CART FUNCTIONS
    // =========================================

    function addToCart(id) {
      const product = products.find(function(item) {
        return item.id === id;
      });

      if (!product) return;

      cart[id] = (cart[id] || 0) + 1;

      renderCart();
      showToast(product.name + ' ditambahkan ke keranjang');
    }

    function changeQuantity(id, change) {
      if (!cart[id]) return;

      cart[id] += change;

      if (cart[id] <= 0) {
        delete cart[id];
      }

      renderCart();
    }

    function getCartSummary() {
      let total = 0;
      let count = 0;

      Object.keys(cart).forEach(function(id) {
        const product = products.find(function(item) {
          return item.id === Number(id);
        });

        if (!product) return;

        total += product.price * cart[id];
        count += cart[id];
      });

      return { total, count };
    }

    function renderCart() {
  const ids = Object.keys(cart);
  const summary = getCartSummary();

  cartCount.textContent = summary.count;
  cartTotal.textContent = formatRupiah(summary.total);
  checkoutButton.disabled = summary.count === 0;

  if (ids.length === 0) {
    cartItems.innerHTML =
      '<div class="empty-cart">' +
        '<div class="emoji">🛍️</div>' +
        '<p>Keranjangmu masih kosong.</p>' +
        '<p>Yuk, pilih menu favoritmu!</p>' +
      '</div>';

    checkoutForm.classList.remove('show');
    return;
  }

  cartItems.innerHTML = ids.map(function(id) {
    const product = products.find(function(item) {
      return item.id === Number(id);
    });

    if (!product) return '';

    return '<div class="cart-item">' +
      '<div>' +
        '<div class="cart-item-name">' +
          escapeHTML(product.name) +
        '</div>' +
        '<div class="cart-item-price">' +
          formatRupiah(product.price * cart[id]) +
        '</div>' +
      '</div>' +
      '<div class="quantity">' +
        '<button data-change="' + id +
        '" data-value="-1">−</button>' +
        '<strong>' + cart[id] + '</strong>' +
        '<button data-change="' + id +
        '" data-value="1">+</button>' +
      '</div>' +
    '</div>';
  }).join('');
}
    // =========================================
    // EVENT LISTENERS
    // =========================================

    document.querySelector('.categories').addEventListener('click', function(event) {
      const button = event.target.closest('[data-category]');

      if (!button) return;

      activeCategory = button.dataset.category;

      document.querySelectorAll('.category-btn').forEach(function(item) {
        item.classList.toggle('active', item === button);
      });

      renderProducts();
    });

    menuGrid.addEventListener('click', function(event) {
      const button = event.target.closest('[data-add]');

      if (!button) return;

      addToCart(Number(button.dataset.add));
    });

    cartItems.addEventListener('click', function(event) {
      const button = event.target.closest('[data-change]');

      if (!button) return;

      changeQuantity(
        Number(button.dataset.change),
        Number(button.dataset.value)
      );
    });

    document.getElementById('cartButton').addEventListener('click', function() {
      document.getElementById('cartSection').scrollIntoView({
        behavior: 'smooth'
      });
    });

    checkoutButton.addEventListener('click', function() {
      checkoutForm.classList.add('show');

      checkoutForm.scrollIntoView({
        behavior: 'smooth',
        block: 'center'
      });
    });

    // =========================================
    // CHECKOUT DEMO
    // =========================================

    checkoutForm.addEventListener('submit', function(event) {
      event.preventDefault();

      const name = document.getElementById('customerName').value.trim();
      const phone = document.getElementById('customerPhone').value.trim();

      if (!name || !phone) {
        showToast('Lengkapi nama dan nomor WhatsApp.');
        return;
      }

      if (!/^[0-9+() -]{8,20}$/.test(phone)) {
        showToast('Format nomor WhatsApp tidak valid.');
        return;
      }

      const summary = getCartSummary();

      if (summary.count === 0) {
        showToast('Keranjang masih kosong.');
        return;
      }

      const orderLines = Object.keys(cart).map(function(id) {
        const product = products.find(function(item) {
          return item.id === Number(id);
        });

        return product.name + ' x' + cart[id];
      });

      const orderText = [
        'PESANAN CRAVE',
        'Nama: ' + name,
        'WhatsApp: ' + phone,
        '',
        ...orderLines,
        '',
        'Total: ' + formatRupiah(summary.total)
      ].join('\\n');

      // Demo checkout: tampilkan ringkasan.
      // Belum menyimpan pesanan ke database.
      window.alert(
        'Pesanan berhasil disiapkan!\\n\\n' + orderText +
        '\\n\\nIni masih demo. Pesanan belum dikirim atau disimpan.'
      );
    });

    // =========================================
    // INITIALIZE
    // =========================================

    renderProducts();
    renderCart();
  </script>

</body>
</html>`;

    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');

    if (req.method === 'HEAD') {
      return res.end();
    }

    return res.end(html);

  } catch (error) {
    console.error('Protected site error:', error);

    res.statusCode = 500;
    return res.end('Internal server error');
  }
}
