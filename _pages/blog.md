---
title: ""
permalink: /blog/
layout: single
share: false
author_profile: true
---
<div class="blog-posts">
  <h1 class="page-title">Latest Posts</h1>

  <div class="post-grid">
    {% for post in site.posts %}
      <article class="post-card">
        {% if post.image %}
          <div class="post-image">
            <img src="{{ post.image }}" alt="{{ post.title }}">
          </div>
        {% endif %}
        <div class="post-content">
          <h2 class="post-title">
            <a href="{{ post.url }}">{{ post.title }}</a>
          </h2>
          <div class="post-meta">
            <time datetime="{{ post.date | date_to_xmlschema }}">
              {{ post.date | date: "%B %-d, %Y" }}
            </time>
          </div>
          <div class="post-excerpt">
            {{ post.excerpt | strip_html | truncatewords: 30 }}
          </div>
          <a href="{{ post.url }}" class="read-more">Read More →</a>
        </div>
      </article>
    {% endfor %}
  </div>
</div>

<style>
  .blog-posts {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
  }

  .page-title {
    color: #2c3e50;
    text-align: center;
    margin-bottom: 3rem;
    font-size: 2.5em;
    font-weight: 700;
  }

  .post-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 2rem;
  }

  .post-card {
    display: flex;
    flex-direction: column;
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 15px rgba(0,0,0,0.1);
    transition: transform 0.3s ease;
    overflow: hidden;
  }

  .post-card:hover {
    transform: translateY(-5px);
  }

  .post-content {
    padding: 1.5rem;
  }

  .post-title {
    margin: 0 0 1rem;
    font-size: 1.5em;
  }

  .post-title a {
    color: #34495e;
    text-decoration: none;
    transition: color 0.2s ease;
  }

  .post-title a:hover {
    color:rgb(16, 12, 7);
  }

  .post-meta {
    color: #7f8c8d;
    font-size: 0.9em;
    margin-bottom: 1rem;
  }

  .post-excerpt {
    color: #666;
    font-size: 0.95em;
    line-height: 1.6;
    margin-bottom: 1rem;
  }

  .read-more {
    display: inline-block;
    color: #e67e22;
    text-decoration: none;
    font-weight: 600;
    transition: color 0.2s ease;
  }

  .read-more:hover {
    color: #d35400;
  }

  .post-image {
    width: 100%;
    height: 200px;
    overflow: hidden;
    position: relative;
  }

  .post-image img {
    width: 100%;
    height: 100%;
    object-fit: cover;
    transition: transform 0.3s ease;
  }

  .post-card:hover .post-image img {
    transform: scale(1.05);
  }

  /* Responsive adjustments */
  @media (max-width: 768px) {
    .post-grid {
      grid-template-columns: 1fr;
    }
    
    .blog-posts {
      padding: 1rem;
    }
  }
</style>

<nav>
  {% for item in site.data.navigation %}
    <a href="{{ item.link }}" {% if page.url == item.link %}style="color: red;"{% endif %}>
      {{ item.name }}
    </a>
  {% endfor %}
</nav>